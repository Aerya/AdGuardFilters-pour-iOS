import unittest
from update_list import is_public_rule, process_rules


class PublicRulesTests(unittest.TestCase):
    def test_local_routing_is_not_exported(self):
        rules = [
            "||media.example.org^$dnsrewrite=NOERROR;A;192.168.1.2,client=192.168.1.59",
            "||media.example.org^$client=~192.168.1.59",
            "||media.example.org^$important,dnsrewrite=192.168.0.1",
        ]
        self.assertEqual(process_rules(rules), set())
        self.assertTrue(all(not is_public_rule(rule) for rule in rules))

    def test_public_blocking_and_exceptions_are_preserved(self):
        rules = {"||ads.example.org^", "@@||safe.example.org^$important", "||tracker.example.org^$third-party"}
        self.assertEqual(process_rules(rules), rules)


if __name__ == "__main__":
    unittest.main()
