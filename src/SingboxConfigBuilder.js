import { SING_BOX_CONFIG, generateRuleSets, generateRules, getOutbounds, PREDEFINED_RULE_SETS} from './config.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { DeepCopy } from './utils.js';
import { t } from './i18n/index.js';

export class SingboxConfigBuilder extends BaseConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent) {
        if (baseConfig === undefined) {
            baseConfig = SING_BOX_CONFIG;
            if (baseConfig.dns && baseConfig.dns.servers) {
                baseConfig.dns.servers[0].detour = t('outboundNames.Node Select');
            }
        }
        super(inputString, baseConfig, lang, userAgent);
        this.selectedRules = selectedRules;
        this.customRules = customRules;
    }

    getProxies() {
        return this.config.outbounds.filter(outbound => outbound?.server != undefined);
    }

    getProxyName(proxy) {
        return proxy.tag;
    }

    convertProxy(proxy) {
        return proxy;
    }

    addProxyToConfig(proxy) {
        // Check if there are proxies with similar tags in existing outbounds
        const similarProxies = this.config.outbounds.filter(p => p.tag && p.tag.includes(proxy.tag));

        // Check if there is a proxy with identical data (excluding the tag)
        const isIdentical = similarProxies.some(p => {
            const { tag: _, ...restOfProxy } = proxy; // Exclude the tag attribute
            const { tag: __, ...restOfP } = p;       // Exclude the tag attribute
            return JSON.stringify(restOfProxy) === JSON.stringify(restOfP);
        });

        if (isIdentical) {
            // If there is a proxy with identical data, skip adding it
            return;
        }

        // If there are proxies with similar tags but different data, modify the tag name
        if (similarProxies.length > 0) {
            proxy.tag = `${proxy.tag} ${similarProxies.length + 1}`;
        }

        this.config.outbounds.push(proxy);
    }

    addAutoSelectGroup(proxyList) { // proxyList is actualProxyTags
        this.config.outbounds = this.config.outbounds || [];
        const autoSelectTag = t('outboundNames.Auto Select');

        this.config.outbounds = this.config.outbounds.filter(o => o.tag !== autoSelectTag);

        this.config.outbounds.unshift({
            type: "urltest",
            tag: autoSelectTag,
            outbounds: DeepCopy(proxyList),
            url: 'http://www.gstatic.com/generate_204',
            interval: "300s"
        });
    }

    addNodeSelectGroup(proxyList) { // proxyList is actualProxyTags
        this.config.outbounds = this.config.outbounds || [];
        const nodeSelectTag = t('outboundNames.Node Select');

        this.config.outbounds = this.config.outbounds.filter(o => o.tag !== nodeSelectTag);

        let selectorOutbounds = [
            t('outboundNames.Auto Select'),
            'DIRECT',
            ...DeepCopy(proxyList)
        ];
        this.config.outbounds.unshift({
            type: "selector",
            tag: nodeSelectTag,
            outbounds: selectorOutbounds
        });
    }

    addOutboundGroups(outbounds, proxyList) { // outbounds are rule names
        this.config.outbounds = this.config.outbounds || [];
        const directDefaultRuleNames = ['Location:CN', 'Private', 'Bilibili'];

        outbounds.forEach(outboundRuleName => {
            const groupTag = t(`outboundNames.${outboundRuleName}`);

            if (this.config.outbounds.find(o => o.tag === groupTag)) {
                return; // Skip if group with this tag already exists
            }

            if (outboundRuleName === 'Ad Block') return; // 'Ad Block' rules use action:reject

            let groupDefinition;
            if (directDefaultRuleNames.includes(outboundRuleName)) {
                groupDefinition = {
                    type: "selector",
                    tag: groupTag,
                    outbounds: [
                        "DIRECT",
                        t('outboundNames.Node Select'),
                        t('outboundNames.Auto Select'),
                        ...DeepCopy(proxyList)
                    ],
                    default: "DIRECT"
                };
            } else {
                groupDefinition = {
                    type: "selector",
                    tag: groupTag,
                    outbounds: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
                };
            }
            this.config.outbounds.push(groupDefinition);
        });
    }

    addCustomRuleGroups(proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        if (Array.isArray(this.customRules)) {
            this.customRules.forEach(rule => {
                const groupTag = t(`outboundNames.${rule.name}`, rule.name);
                if (!this.config.outbounds.find(o => o.tag === groupTag)) {
                    this.config.outbounds.push({
                        type: "selector",
                        tag: groupTag,
                        outbounds: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
                    });
                }
            });
        }
    }

    addFallBackGroup(proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        const fallBackTag = t('outboundNames.Fall Back');
        if (!this.config.outbounds.find(o => o.tag === fallBackTag)) {
            this.config.outbounds.push({
                type: "selector",
                tag: fallBackTag,
                outbounds: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
            });
        }
    }

    formatConfig() {
        // Note: Outbound building methods (addAutoSelectGroup, etc.) are called by BaseConfigBuilder.addSelectors()
        // which is called by BaseConfigBuilder.build()

        const generatedRules = generateRules(this.selectedRules, this.customRules);
        const { site_rule_sets, ip_rule_sets } = generateRuleSets(this.selectedRules, this.customRules);

        this.config.route.rule_set = [...site_rule_sets, ...ip_rule_sets];
        this.config.route.rules = [];

        const adBlockOutboundName = 'Ad Block';

        generatedRules.forEach(rule => {
            const ruleConfig = {};
            if (rule.domain_suffix && rule.domain_suffix.length > 0 && rule.domain_suffix.some(d => d !== '')) {
                ruleConfig.domain_suffix = rule.domain_suffix.filter(d => d !== '');
            }
            if (rule.domain_keyword && rule.domain_keyword.length > 0 && rule.domain_keyword.some(d => d !== '')) {
                ruleConfig.domain_keyword = rule.domain_keyword.filter(d => d !== '');
            }
            if (rule.protocol && rule.protocol.length > 0 && rule.protocol.some(p => p !== '')) {
                ruleConfig.protocol = rule.protocol.filter(p => p !== '');
            }

            const siteRuleSetNames = rule.site_rules && rule.site_rules.length > 0 && rule.site_rules[0] !== '' ? rule.site_rules : [];
            const ipRuleSetNames = rule.ip_rules && rule.ip_rules.filter(ip => ip.trim() !== '').map(ip => `${ip.trim()}-ip`);
            const combinedRuleSets = [...siteRuleSetNames, ...ipRuleSetNames].filter(rs => rs !== '');

            if (combinedRuleSets.length > 0) {
                ruleConfig.rule_set = combinedRuleSets;
            }

            if (rule.ip_cidr && rule.ip_cidr.length > 0 && rule.ip_cidr.some(ip => ip !== '')) {
                ruleConfig.ip_cidr = rule.ip_cidr.filter(ip => ip !== '');
            }

            const hasMatchers = ruleConfig.domain_suffix || ruleConfig.domain_keyword || ruleConfig.rule_set || ruleConfig.ip_cidr || ruleConfig.protocol;

            if (hasMatchers) {
                if (rule.outbound === adBlockOutboundName) {
                    ruleConfig.action = "reject";
                } else {
                    ruleConfig.outbound = t(`outboundNames.${rule.outbound}`);
                }
                this.config.route.rules.push(ruleConfig);
            }
        });

        this.config.route.rules.unshift(
            { clash_mode: 'direct', outbound: 'DIRECT' },
            { clash_mode: 'global', outbound: t('outboundNames.Node Select') },
            { action: 'sniff' },
            { protocol: 'dns', action: 'hijack-dns' }
        );

        this.config.route.auto_detect_interface = true;
        this.config.route.final = t('outboundNames.Fall Back'); // Updated final route to Fall Back

        return this.config;
    }
}