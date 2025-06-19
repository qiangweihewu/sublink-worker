import yaml from 'js-yaml';
import { CLASH_CONFIG, generateRules, generateClashRuleSets, getOutbounds, PREDEFINED_RULE_SETS } from './config.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { DeepCopy } from './utils.js';
import { t } from './i18n/index.js';

export class ClashConfigBuilder extends BaseConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent) {
        if (!baseConfig) {
            baseConfig = CLASH_CONFIG;
        }
        super(inputString, baseConfig, lang, userAgent);
        this.selectedRules = selectedRules;
        this.customRules = customRules;
    }

    getProxies() {
        return this.config.proxies || [];
    }

    getProxyName(proxy) {
        return proxy.name;
    }

    convertProxy(proxy) {
        switch(proxy.type) {
            case 'shadowsocks':
                return {
                    name: proxy.tag,
                    type: 'ss',
                    server: proxy.server,
                    port: proxy.server_port,
                    cipher: proxy.method,
                    password: proxy.password
                };
            case 'vmess':
                return {
                    name: proxy.tag,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.server_port,
                    uuid: proxy.uuid,
                    alterId: proxy.alter_id,
                    cipher: proxy.security,
                    tls: proxy.tls?.enabled || false,
                    servername: proxy.tls?.server_name || '',
                    network: proxy.transport?.type || 'tcp',
                    'ws-opts': proxy.transport?.type === 'ws' ? {
                        path: proxy.transport.path,
                        headers: proxy.transport.headers
                    } : undefined
                };
            case 'vless':
                return {
                    name: proxy.tag,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.server_port,
                    uuid: proxy.uuid,
                    cipher: proxy.security,
                    tls: proxy.tls?.enabled || false,
                    'client-fingerprint': proxy.tls.utls?.fingerprint,
                    servername: proxy.tls?.server_name || '',
                    network: proxy.transport?.type || 'tcp',
                    'ws-opts': proxy.transport?.type === 'ws' ? {
                        path: proxy.transport.path,
                        headers: proxy.transport.headers
                    }: undefined,
                    'reality-opts': proxy.tls.reality?.enabled ? {
                        'public-key': proxy.tls.reality.public_key,
                        'short-id': proxy.tls.reality.short_id,
                    } : undefined,
                    'grpc-opts': proxy.transport?.type === 'grpc' ? {
                        'grpc-service-name': proxy.transport.service_name,
                    } : undefined,
                    tfo : proxy.tcp_fast_open,
                    'skip-cert-verify': proxy.tls.insecure,
                    'flow': proxy.flow ?? undefined,
                };
            case 'hysteria2':
                return {
                    name: proxy.tag,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.server_port,
                    obfs: proxy.obfs.type,
                    'obfs-password': proxy.obfs.password,
                    password: proxy.password,
                    auth: proxy.auth,
                    up: proxy.up_mbps,
                    down: proxy.down_mbps,
                    'recv-window-conn': proxy.recv_window_conn,
                    sni: proxy.tls?.server_name || '',
                    'skip-cert-verify': proxy.tls?.insecure || true,
                };
            case 'trojan':
                return {
                    name: proxy.tag,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.server_port,
                    password: proxy.password,
                    cipher: proxy.security,
                    tls: proxy.tls?.enabled || false,
                    'client-fingerprint': proxy.tls.utls?.fingerprint,
                    sni: proxy.tls?.server_name || '',
                    network: proxy.transport?.type || 'tcp',
                    'ws-opts': proxy.transport?.type === 'ws' ? {
                        path: proxy.transport.path,
                        headers: proxy.transport.headers
                    }: undefined,
                    'reality-opts': proxy.tls.reality?.enabled ? {
                        'public-key': proxy.tls.reality.public_key,
                        'short-id': proxy.tls.reality.short_id,
                    } : undefined,
                    'grpc-opts': proxy.transport?.type === 'grpc' ? {
                        'grpc-service-name': proxy.transport.service_name,
                    } : undefined,
                    tfo : proxy.tcp_fast_open,
                    'skip-cert-verify': proxy.tls.insecure,
                    'flow': proxy.flow ?? undefined,
                };
            case 'tuic':
                return {
                    name: proxy.tag,
                    type: proxy.type,
                    server: proxy.server,
                    port: proxy.server_port,
                    uuid: proxy.uuid,
                    password: proxy.password,
                    'congestion-controller': proxy.congestion,
                    'skip-cert-verify': proxy.tls.insecure,
                    'disable-sni': true,
                    'alpn': proxy.tls.alpn,
                    'sni': proxy.tls.server_name,
                    'udp-relay-mode': 'native',
                };
            default:
                return proxy; // Return as-is if no specific conversion is defined
        }
    }

    addProxyToConfig(proxy) {
        this.config.proxies = this.config.proxies || [];
    
        // Find proxies with the same or partially matching name
        const similarProxies = this.config.proxies.filter(p => p.name.includes(proxy.name));
    
        // Check if there is a proxy with identical data excluding the 'name' field
        const isIdentical = similarProxies.some(p => {
            const { name: _, ...restOfProxy } = proxy; // Exclude the 'name' attribute
            const { name: __, ...restOfP } = p;       // Exclude the 'name' attribute
            return JSON.stringify(restOfProxy) === JSON.stringify(restOfP);
        });
    
        if (isIdentical) {
            // If there is a proxy with identical data, skip adding it
            return;
        }
    
        // If there are proxies with similar names but different data, modify the name
        if (similarProxies.length > 0) {
            proxy.name = `${proxy.name} ${similarProxies.length + 1}`;
        }
    
        // Add the proxy to the configuration
        this.config.proxies.push(proxy);
    }

    // 生成规则
    _generateRules() { // Renamed to avoid conflict if BaseConfigBuilder has generateRules
        return generateRules(this.selectedRules, this.customRules);
    }

    addAutoSelectGroup(proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        // Ensure 'Auto Select' is not added if it already exists
        if (!this.config['proxy-groups'].find(g => g.name === t('outboundNames.Auto Select'))) {
            this.config['proxy-groups'].push({
                name: t('outboundNames.Auto Select'),
                type: 'url-test',
                proxies: DeepCopy(proxyList),
                url: 'http://www.gstatic.com/generate_204',
                interval: 300,
                lazy: false
            });
        }
    }

    addNodeSelectGroup(proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        const nodeSelectGroupName = t('outboundNames.Node Select');
        // Remove if already exists to re-add at unshift position
        this.config['proxy-groups'] = this.config['proxy-groups'].filter(g => g.name !== nodeSelectGroupName);

        let selectorProxies = [
            'DIRECT',
            'REJECT',
            t('outboundNames.Auto Select'),
            ...DeepCopy(proxyList)
        ];
        this.config['proxy-groups'].unshift({
            type: "select",
            name: nodeSelectGroupName,
            proxies: selectorProxies
        });
    }

    addOutboundGroups(outbounds, proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        outbounds.forEach(outboundRuleName => {
            const groupName = t(`outboundNames.${outboundRuleName}`);
            if (!this.config['proxy-groups'].find(g => g.name === groupName)) {
                this.config['proxy-groups'].push({
                    type: "select",
                    name: groupName,
                    proxies: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
                });
            }
        });
    }

    addCustomRuleGroups(proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        if (Array.isArray(this.customRules)) {
            this.customRules.forEach(rule => {
                const groupName = t(`outboundNames.${rule.name}`, rule.name);
                if (!this.config['proxy-groups'].find(g => g.name === groupName)) {
                    this.config['proxy-groups'].push({
                        type: "select",
                        name: groupName,
                        proxies: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
                    });
                }
            });
        }
    }

    addFallBackGroup(proxyList) {
        this.config['proxy-groups'] = this.config['proxy-groups'] || [];
        const fallBackGroupName = t('outboundNames.Fall Back');
        if (!this.config['proxy-groups'].find(g => g.name === fallBackGroupName)) {
            this.config['proxy-groups'].push({
                type: "select",
                name: fallBackGroupName,
                proxies: [t('outboundNames.Node Select'), ...DeepCopy(proxyList)]
            });
        }
    }

    formatConfig() {
        // Ensure proxies are initialized
        this.config.proxies = this.config.proxies || [];

        // Note: Group building methods (addAutoSelectGroup, etc.) are called by BaseConfigBuilder.addSelectors()
        // which is called by BaseConfigBuilder.build()

        const rulesFromConfigJs = this._generateRules();
        const ruleResults = [];
        
        const { site_rule_providers, ip_rule_providers } = generateClashRuleSets(this.selectedRules, this.customRules);
        
        this.config['rule-providers'] = {
            ...site_rule_providers,
            ...ip_rule_providers
        };

        rulesFromConfigJs.forEach(rule => {
            // For Ad Block rules, target REJECT directly. Otherwise, target the translated group name.
            const targetGroupOrPolicy = (rule.outbound === 'Ad Block')
                ? 'REJECT'
                : t(`outboundNames.${rule.outbound}`);

            if (rule.domain_suffix && rule.domain_suffix.length > 0) {
                rule.domain_suffix.forEach(suffix => {
                    if (suffix) ruleResults.push(`DOMAIN-SUFFIX,${suffix},${targetGroupOrPolicy}`);
                });
            }
            if (rule.domain_keyword && rule.domain_keyword.length > 0) {
                rule.domain_keyword.forEach(keyword => {
                    if (keyword) ruleResults.push(`DOMAIN-KEYWORD,${keyword},${targetGroupOrPolicy}`);
                });
            }
            if (rule.site_rules && rule.site_rules.length > 0 && rule.site_rules[0] !== '') {
                 rule.site_rules.forEach(site => {
                    if (site) ruleResults.push(`RULE-SET,${site},${targetGroupOrPolicy}`);
                });
            }
            if (rule.ip_rules && rule.ip_rules.length > 0 && rule.ip_rules[0] !== '') {
                rule.ip_rules.forEach(ip => {
                    if (ip) ruleResults.push(`RULE-SET,${ip},${targetGroupOrPolicy},no-resolve`);
                });
            }
            if (rule.ip_cidr && rule.ip_cidr.length > 0) {
                 rule.ip_cidr.forEach(cidr => {
                    if (cidr) ruleResults.push(`IP-CIDR,${cidr},${targetGroupOrPolicy},no-resolve`);
                });
            }
        });

        this.config.rules = ruleResults;
        // The final MATCH rule should point to Fall Back group
        this.config.rules.push(`MATCH,${t('outboundNames.Fall Back')}`);

        return yaml.dump(this.config);
    }
}
