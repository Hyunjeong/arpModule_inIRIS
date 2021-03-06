package etri.sdn.controller.module.firewall;

import org.openflow.protocol.OFMatch;

/**
 * This class consists of the {@link FirewallRule} and the wildcards 
 * for the firewall decision.
 */
public class RuleWildcardsPair {
    public FirewallRule rule;
    public int wildcards = OFMatch.OFPFW_ALL;
}
