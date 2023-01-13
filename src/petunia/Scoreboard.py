"""Scoreboard.py

Implement interface scoreboarding.

Initial setup works similar to slicing.
"""

import logging

from petunia.Topology import (
    Topology,
    sortIfNames,
)

from petunia.Slicer import SlicerBase

VLAN_TAG_ALL_INTERFACES = True
# collapse vlan-tagged rules that cover all tagged interfaces

VLAN_TAG_ALL_VIDS = True
# collapse vlan-tagged rules that cover all defined (tagged) vids

class Scoreboard(SlicerBase):

    def expandRule(self, rule, allInterfaces):
        """Generate a minimal representation of this rule.

        The rule may have multiple tagged and untagged interfaces.
        """

        a = set(allInterfaces)
        r = set(rule.in_interfaces)

        missing = a.difference(r)
        extra = r.difference(a)

        for ifName in sortIfNames(extra):
            self.log.warn("extra interface %s in rule", ifName)

        # widest possible set of interfaces --> no interface specifier
        if not missing:
            yield rule
        else:
            # worst case, we need to emit the rule for each interface
            # here, only emit rules for onlyInterfaces
            if len(missing) < 4:
                missing_ = sortIfNames(missing)
                self.log.debug("rule is missing %d interfaces (%s), exploding",
                               len(missing), ", ".join(missing_))
            else:
                missing_ = sortIfNames(missing)[:4]
                self.log.debug("rule is missing %d interfaces (%s ...), exploding",
                               len(missing), ", ".join(missing_))
            emitInterfaces = set()
            emitInterfaces.update(rule.in_interfaces)
            emitInterfaces.intersection_update(a)
            if self.onlyInterfaces is not None:
                emitInterfaces.intersection_update(self.onlyInterfaces)
            for ifName in sortIfNames(emitInterfaces):
                newRule = rule.clone()
                newRule.in_interface = ifName
                yield newRule

        if not rule.in_vlans_tagged:
            return

        # here, vlans get really messy

        # if this rule matches a vlan-tagged port for all of our
        # defined vlans,
        # then we can ignore the input port and just match on
        # a genericvlan tag

        if VLAN_TAG_ALL_VIDS:
            if self.vlansTagged == set(rule.in_vlans_tagged.keys()):
                vidRule = rule.clone()
                vidRule.args[0:0] = ['-m', 'vlan', '--vlan-tag', 'any',]
                vidRule.in_interface = None

                yield vidRule
                return

        # worst case
        # for each tag, expand the rule with the vlan tag specifier added

        for vid in sorted(rule.in_vlans_tagged.keys()):
            ifNames = rule.in_vlans_tagged[vid]

            vidRule = rule.clone()
            vidRule.args[0:0] = ['-m', 'vlan', '--vlan-tag', str(vid),]
            vidRule.in_interface = None

            vidRule.in_interfaces = ifNames
            vidRule.in_interfaces_tagged = {}
            vidRule.in_vlans_tagged = {}
            # ha ha pretend this is actually untagged
            # (break the recursion)

            if VLAN_TAG_ALL_INTERFACES:
                # if this rule matches a given vid
                # across *all* interfaces we are trunking for this vid,
                # then this is equivalent to "all interfaces"

                # XXX rothcar -- this should trivially match for all vlans,
                # since the tagged interface population is based on the original
                # vlan memberships

                allInterfaces_ = set(x[0] for x in self.topo.getVlanPorts(vid).items() if x[1])
            else:
                allInterfaces_ = allInterfaces

            for vidRule_ in self.expandRule(vidRule, allInterfaces_):
                yield vidRule_

    def scoreboard(self):
        """Scoreboard the rules by interface group."""

        self.visitInterfaces()

        def _hasInterfaces(rule):
            if rule.in_interfaces: return True
            if rule.in_interfaces_tagged: return True
            return False

        rootChain = self.table.chains[self.chain]
        rules = list([x for x in rootChain.rules if _hasInterfaces(x)])

        if not self.interfacesUntagged and not self.interfacesTagged:
            if len(rootChain):
                raise ValueError("no interfaces found for scoreboarding")
        if not rules:
            self.log.warning("no rules found for scoreboarding")

        table_ = self.table.clone()
        table_.chains[self.chain] = self.table.chain_klass([], rootChain.policy)

        # label each rule with an input-free hash
        for rule in rules:
            simpleRule = rule.clone()
            simpleRule.in_interface = None
            rule.hash_simple = hash(simpleRule)

        a = self.allInterfaces or self.topo.getPorts()
        a = set(a)

        # enumerate all rules with the same hash_simple, collapse them
        rules_, rules = rules, []
        baseRule = None
        cnt = 0
        while True:

            if baseRule is None and not rules_: break

            if baseRule is None:
                rule0 = rules_.pop(0)
                baseRule = rule0.clone()
                baseRule.hash_simple = rule0.hash_simple
                baseRule.in_interface = None
                baseRule.in_interfaces = set(rule0.in_interfaces)
                baseRule.in_interfaces_tagged = dict(rule0.in_interfaces_tagged)
                baseRule.in_vlans_tagged = dict(rule0.in_vlans_tagged)
                cnt += 1
                continue

            if not rules_:
                newRules = list(self.expandRule(baseRule, allInterfaces=a))
                if cnt != len(newRules):
                    self.log.debug("scoreboarded %d --> %d rules (%d untagged, %d tagged interfaces)",
                                   cnt, len(newRules),
                                   len(baseRule.in_interfaces),
                                   len(baseRule.in_interfaces_tagged))
                table_.chains[self.chain].rules.extend(newRules)
                baseRule = None
                cnt = 0
                continue

            if baseRule.hash_simple != rules_[0].hash_simple:
                newRules = list(self.expandRule(baseRule, allInterfaces=a))
                if cnt != len(newRules):
                    self.log.debug("scoreboarded %d --> %d rules (%d untagged, %d tagged interfaces)",
                                   cnt, len(newRules),
                                   len(baseRule.in_interfaces),
                                   len(baseRule.in_interfaces_tagged))
                table_.chains[self.chain].rules.extend(newRules)
                baseRule = None
                cnt = 0
                continue

            # else, collapse these two rules
            rule0 = rules_.pop(0)
            baseRule.in_interfaces.update(rule0.in_interfaces)
            for ifName, vids in rule0.in_interfaces_tagged.items():
                baseRule.in_interfaces_tagged.setdefault(ifName, set())
                baseRule.in_interfaces_tagged[ifName].update(vids)
            for vid, ifNames in rule0.in_vlans_tagged.items():
                baseRule.in_vlans_tagged.setdefault(vid, set())
                baseRule.in_vlans_tagged[vid].update(ifNames)
            cnt += 1

        return table_

def validateScoreboard(chain, interfaces, extended=True):
    """Validate this is an output from iptables-scoreboard.

    Generally, this means, no inter-chain jumps or skips.
    """

    ifSet = set(interfaces)
    for rule in chain.rules:
        if (rule.in_interface is not None
            and rule.in_interface not in ifSet):
            raise ValueError("invalid in_interfaces in rule %s"
                             % rule)
        if extended:
            if rule.target not in ('ACCEPT', 'DROP',
                                   'REJECT',
                                   'LOG',):
                raise ValueError("invalid target %s in rule" % rule.target)
        else:
            if rule.target not in ('ACCEPT', 'DROP',
                                   'REJECT',):
                raise ValueError("invalid target %s in rule" % rule.target)
