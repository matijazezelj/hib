import { describe, expect, test } from "bun:test";
import { programOf } from "../src/events";

const check = (cases: [string, string][]) => {
  for (const [cmd, want] of cases) expect([cmd, programOf(cmd)]).toEqual([cmd, want]);
};

describe("programOf", () => {
  test("keeps the existing labels", () => {
    check([
      ["FOO=1 BAR=2 env -i ./scripts/deploy.sh --prod", "deploy.sh"],
      ["sudo -u root curl https://example.com", "curl"],
      ["sudo --user=root -E VAR=1 /usr/bin/git push", "git"],
      ["bash -c 'curl https://example.com'", "curl"],
      ['sh -ec "npm test"', "npm"],
      ['env -S "python3 -u" x', "python3"],
      ["timeout 10 nice -n 5 make", "make"],
      ["time -f %e ./run.sh", "run.sh"],
      ["cat x | curl -d @- https://e.com", "cat"],
      ["  ", "[COMMAND]"],
      ["", "[COMMAND]"],
    ]);
  });

  test("a quoted assignment value is one word, never the label", () => {
    check([
      ['DB_PASSWORD="correct horse battery" psql', "psql"],
      ["DB_PASSWORD='correct horse battery' psql -h db", "psql"],
      ['env FOO="a b" curl', "curl"],
      ['sudo FOO="a b c" curl', "curl"],
      ["A=x\\ y\\ z curl", "curl"],
      ['A="it\'s \\"quoted\\" here" curl', "curl"],
      ["A='a \"b\" c' B=\"d 'e' f\" make", "make"],
      ['A="multi\nline secret" curl', "curl"],
    ]);
  });

  test("a command substitution at or before the program fails closed", () => {
    check([
      ['A="$(cat /etc/passwd)" curl', "[COMMAND]"],
      ["A=$(cat /etc/passwd) curl", "[COMMAND]"],
      ["A=`cat /etc/passwd` curl", "[COMMAND]"],
      ['A="`cat /etc/passwd`" curl', "[COMMAND]"],
      ["$(which curl) https://e.com", "[COMMAND]"],
      ["`which curl` x", "[COMMAND]"],
      ["sudo -u $(whoami) curl", "[COMMAND]"],
      ["sudo -u `whoami` curl", "[COMMAND]"],
      ["env -S \"$(cat secret)\" x", "[COMMAND]"],
      ["A=$'secret\\x20word' curl", "[COMMAND]"],
      ["$'\\x63url' x", "[COMMAND]"],
      ["bash -c '$(cat /etc/passwd)'", "[COMMAND]"],
      ["A=$(echo $(id)) curl", "[COMMAND]"],
    ]);
  });

  test("a substitution after the program word is fine", () => {
    check([
      ['curl "$(cat x)"', "curl"],
      ["curl $(cat x) `id`", "curl"],
      ["bash -c 'curl \"$(cat token)\" https://e.com'", "curl"],
      ['sh -c "curl $(cat token)"', "curl"],
      ["sudo -u root curl -H \"Authorization: $(cat t)\"", "curl"],
    ]);
  });

  test("$( and backticks inside single quotes are literal", () => {
    check([
      ["A='$(cat /etc/passwd)' curl", "curl"],
      ["A='`id`' curl", "curl"],
      ["A='a(b)c' curl", "curl"],
    ]);
  });

  test("unbalanced input fails closed", () => {
    check([
      ['A="unterminated secret psql', "[COMMAND]"],
      ["A='unterminated secret psql", "[COMMAND]"],
      ["A=$(cat x curl", "[COMMAND]"],
      ["A=`cat x curl", "[COMMAND]"],
      ["curl x \\", "[COMMAND]"],
      ['curl "x', "[COMMAND]"],
      ["A=$'abc curl", "[COMMAND]"],
      ['bash -c "curl \'x"', "[COMMAND]"],
    ]);
  });

  test("the label never holds whitespace, = or $", () => {
    check([
      ['"my secret pass" x', "[COMMAND]"],
      ["'a b' x", "[COMMAND]"],
      ["$CMD x", "[COMMAND]"],
      ["${CMD} x", "[COMMAND]"],
      ["./a=b x", "[COMMAND]"],
      ['"/usr/local/bin/my tool" x', "[COMMAND]"],
      ['"/usr/bin/curl" x', "curl"],
      ["'curl' x", "curl"],
      ["$HOME/bin/tool x", "tool"],
    ]);
  });

  test("separators end words; only the first command is labelled", () => {
    check([
      ["(curl x)", "curl"],
      ["curl x; rm -rf /", "curl"],
      ["curl x&&wget y", "curl"],
      ["cat x|curl y", "cat"],
      ["A=(secret words) curl", "[COMMAND]"],
      ["f() { curl x; }", "[COMMAND]"],
    ]);
  });

  test("names from Object.prototype are plain programs, not wrappers", () => {
    check([
      ["toString -x", "toString"],
      ["constructor a b", "constructor"],
      ["__proto__ x", "__proto__"],
    ]);
  });

  test("sudo options that take a value", () => {
    check([
      ["sudo -R /root curl", "curl"],
      ["sudo --chroot /root curl", "curl"],
      ["sudo --chroot=/root curl", "curl"],
      ["sudo -R/root curl", "curl"],
      ["sudo -a bsdauth curl", "curl"],
      ["sudo --auth-type bsdauth curl", "curl"],
      ["sudo -c staff curl", "curl"],
      ["sudo --login-class staff curl", "curl"],
      ["sudo -D /tmp curl", "curl"],
      ["sudo -g wheel -u admin curl", "curl"],
      ["sudo -h host curl", "curl"],
      ["sudo -C 3 -T 60 -r role -t type -U other -p pw curl", "curl"],
    ]);
  });

  test("grouped short options read the value like getopt", () => {
    check([
      ["sudo -Eu admin curl", "curl"],
      ["sudo -iu admin curl", "curl"],
      ["sudo -Euadmin curl", "curl"],
      ["sudo -nE curl", "curl"],
      ["sudo -uadmin curl", "curl"],
      ["nice -n5 make", "make"],
      ["doas -a style -u admin curl", "curl"],
    ]);
  });

  test("env options that take a value", () => {
    check([
      ["env -a fakename curl", "curl"],
      ["env --argv0 fakename curl", "curl"],
      ["env --argv0=fakename curl", "curl"],
      ["env -P /opt/bin curl", "curl"],
      ["env -u SECRET -C /tmp curl", "curl"],
      ["env -i -- curl", "curl"],
    ]);
  });

  test("env -S in every form", () => {
    check([
      ['env -S "python3 -u" x', "python3"],
      ["env -S'python3 -u' x", "python3"],
      ['env -S"python3 -u" x', "python3"],
      ["env -Spython3 x", "python3"],
      ['env --split-string="python3 -u" x', "python3"],
      ["env --split-string 'python3 -u' x", "python3"],
      ['env -iS "python3 -u" x', "python3"],
      ['env -S "FOO=1 node app.js"', "node"],
      ['env -S "sudo -u root curl"', "curl"],
      ["env -S", "[COMMAND]"],
      ["env --split-string", "[COMMAND]"],
    ]);
  });

  test("recursion depth is bounded and fails closed", () => {
    check([
      ["env -S 'env -S \"env -S curl\"'", "curl"],
      ["env -S 'env -S \"env -S \\\"env -S curl\\\"\"'", "[COMMAND]"],
      ["bash -c 'bash -c \"curl x\"'", "curl"],
    ]);
  });
});
