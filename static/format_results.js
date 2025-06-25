function formatResults(data) {
    let plainText = '';
    data.forEach(result => {
        plainText += `Observable: ${result.observable}\nType: ${result.type}\n`;

        if (result.rdap) {
            if (result.rdap) {
                plainText += `RDAP:\n`;
                if (result.rdap.registrar) plainText += `- Registrar: ${result.rdap.registrar}\n`;
                if (result.rdap.abuse_contact) plainText += `- Abuse Contact: ${result.rdap.abuse_contact}\n`;
                if (result.rdap.registrant) plainText += `- Registrant: ${result.rdap.registrant}\n`;
                if (result.rdap.organization) plainText += `- Organization: ${result.rdap.organization}\n`;
                if (result.rdap.registrant_email) plainText += `- Registrant Email: ${result.rdap.registrant_email}\n`;
                if (result.rdap.creation_date) plainText += `- Creation Date: ${result.rdap.creation_date}\n`;
                if (result.rdap.expiration_date) plainText += `- Expiration Date: ${result.rdap.expiration_date}\n`;
                if (result.rdap.update_date) plainText += `- Updated Date: ${result.rdap.update_date}\n`;
                if (result.rdap.name_servers && result.rdap.name_servers.length > 0) {
                    plainText += `- Name Servers: ${result.rdap.name_servers.join(', ')}\n`;
                }
            }
        }

        if (result.reverse_dns) {
            plainText += `Reverse DNS (local DNS): ${result.reverse_dns.reverse_dns.join(', ')}\n`;
        }

        if (result.abusix) {
            plainText += `Abusix (abuse contact for IP): ${result.abusix.abuse}\n`;
        }

        if (result.extension) {
            plainText += `Extension: ${result.extension.name}\n`;
            plainText += `URL: ${result.extension.url}\n`;
        }

        if (result.google_dns && result.google_dns.Answer && result.google_dns.Answer.length > 0) {
            plainText += `Google DNS (common records):\n`;
            result.google_dns.Answer.forEach(dnsRecord => {
                plainText += `  - Type: ${dnsRecord.type_name}, Data: ${dnsRecord.data}`;
                if (dnsRecord.name) plainText += `, Name: ${dnsRecord.name}`;
                plainText += `\n`;
            });
        }

        if (result.ipquery) {
            plainText += `IPquery: Geolocation: ${result.ipquery.geolocation}, Country: ${result.ipquery.country_name}, ASN: ${result.ipquery.asn} ${result.ipquery.isp}, Risk Score: ${result.ipquery.risk_score}, Proxy: ${result.ipquery.is_proxy}, Tor: ${result.ipquery.is_tor}, VPN: ${result.ipquery.is_vpn}\n`;
        }
        if (result.ipinfo) {
            plainText += `IPinfo: Geolocation: ${result.ipinfo.geolocation}, Country: ${result.ipinfo.country_name}, ASN: ${result.ipinfo.asn}\n`;
        }
        if (result.abuseipdb) {
            plainText += `AbuseIPDB: Reports: ${result.abuseipdb.reports}, Risk Score: ${result.abuseipdb.risk_score}\n`;
        }
        if (result.spur) {
            plainText += `Spur: Tunnels: ${result.spur.tunnels}\n`;
        }
        if (result.webscout) {
            plainText += `WebScout: `;
            if (result.webscout.risk_score) plainText += `Risk Score: ${result.webscout.risk_score}, `;
            if (result.webscout.is_vpn) {
                plainText += ` - VPN: ${result.webscout.is_vpn}\n`;
            }
            if (result.webscout.is_tor) {
                plainText += ` - Tor: ${result.webscout.is_tor}\n`;
            }
            if (result.webscout.is_proxy) {
                plainText += ` - Proxy: ${result.webscout.is_proxy}\n`;
            }
            if (result.webscout.country_name) plainText += `Country: ${result.webscout.country_name}, `;
            if (result.webscout.hostnames) plainText += `Hostnames: ${result.webscout.hostnames.join(', ')}, `;
            if (result.webscout.asn) plainText += `ASN: ${result.webscout.asn} ${result.webscout.as_org}\n`;
            if (result.webscout.description) plainText += ` - Description: ${result.webscout.description}\n`;
            if (result.webscout.domains_on_ip) plainText += ` - Domains on IP: ${result.webscout.domains_on_ip}\n`;
            if (result.webscout.network_type) plainText += ` - Type: ${result.webscout.network_type}\n`;
            if (result.webscout.network_service) plainText += ` - Network Service: ${result.webscout.network_service}\n`;
            if (result.webscout.network_service_region) plainText += ` - Network Service Region: ${result.webscout.network_service_region}\n`;
            if (result.webscout.network_provider_services.length > 0) plainText += ` - Services: ${result.webscout.network_provider_services.join(', ')}\n`;
            if (result.webscout.behavior) plainText += ` - Behavior: ${result.webscout.behavior.join(', ')}\n`;
            if (result.webscout.open_ports) plainText += ` - Open Ports: ${result.webscout.open_ports.join(', ')}\n`;
        }

        if (result.virustotal) {
            plainText += `VirusTotal: Detection Ratio: ${result.virustotal.detection_ratio}, Community Score: ${result.virustotal.community_score}\n`;
        }
        if (result.mde) {
            plainText += `Microsoft Defender for Endpoint: Prevalence: ${result.mde.organizationPrevalence}, First Seen: ${result.mde.orgFirstSeen}, Last Seen: ${result.mde.orgLastSeen}\n`;
        }
        if (result.google_safe_browsing) {
            plainText += `Google Safe Browsing: ${result.google_safe_browsing.threat_found}\n`;
        }
        if (result.shodan) {
            plainText += `Shodan: Ports: ${result.shodan.ports.join(', ')}${result.shodan.tags.length > 0 ? `, Tags: ${result.shodan.tags.join(', ')}` : ''}\n`;
        }
        if (result.phishtank) {
            plainText += `Phishtank: In Database: ${result.phishtank.in_database}\n`;
        }

        if (result.threatfox && result.threatfox.count > 0) {
            plainText += `ThreatFox: Count: ${result.threatfox.count}, Malware: ${result.threatfox.malware_printable.join(', ')}\n`;
        }
        if (result.google && result.google.results.length > 0) {
            plainText += `Google:\n`;
            result.google.results.forEach(googleResult => {
                plainText += `  - ${googleResult.title}: ${googleResult.url}\n`;
            });
        }
        if (result.github && result.github.results.length > 0) {
            plainText += `Github:\n`;
            result.github.results.forEach(githubResult => {
                plainText += `  - ${githubResult.title}: ${githubResult.url}\n`;
            });
        }
        if (result.ioc_one_html && result.ioc_one_html.results.length > 0) {
            plainText += `Ioc.One (HTML):\n`;
            result.ioc_one_html.results.forEach(iocOneHtmlResult => {
                plainText += `  - ${iocOneHtmlResult.title}: ${iocOneHtmlResult.source}\n`;
            });
        }
        if (result.ioc_one_pdf && result.ioc_one_pdf.results.length > 0) {
            plainText += `Ioc.One (PDF):\n`;
            result.ioc_one_pdf.results.forEach(iocOnePdfResult => {
                plainText += `  - ${iocOnePdfResult.title}: ${iocOnePdfResult.source}\n`;
            });
        }
        if (result.urlscan && result.urlscan.scan_count > 0) {
            plainText += `URLscan: Scan Count: ${result.urlscan.scan_count}\n`;
            result.urlscan.top_domains.forEach(domain => {
                plainText += `  - ${domain.domain} (${domain.count})\n`;
            });
        }
        if (result.crtsh && result.crtsh.scan_count > 0) {
            plainText += `crt.sh: Scan Count: ${result.urlscan.scan_count}\n`;
            result.crtsh.top_domains.forEach(domain => {
                plainText += `  - ${domain.domain} (${domain.count})\n`;
            });
        }
        if (result.opencti && result.opencti.global_count > 0) {
            plainText += `OpenCTI:\n`;
            plainText += `  - Global Count: ${result.opencti.global_count}\n`;
            plainText += `  - Entity Counts:\n`;
            for (const [entity, count] of Object.entries(result.opencti.entity_counts)) {
                plainText += `    - ${entity}: ${count}\n`;
            }
            plainText += `  - Search Link: ${result.opencti.search_link}\n`;
            plainText += `  - Latest Entity Created At: ${result.opencti.latest_created_at}\n`;
            plainText += `  - Latest Indicator Name: ${result.opencti.latest_indicator_name}\n`;
            if (result.opencti.latest_indicator_link) {
                plainText += `  - Latest Indicator Link: ${result.opencti.latest_indicator_link}\n`;
                plainText += `  - OpenCTI Score: ${result.opencti.x_opencti_score} / 100\n`;
                plainText += `  - Confidence: ${result.opencti.confidence}\n`;
                plainText += `  - Revoked: ${result.opencti.revoked}\n`;
                plainText += `  - Valid From: ${result.opencti.valid_from}\n`;
                plainText += `  - Valid Until: ${result.opencti.valid_until}\n`;
            }
        }

        if (result.misp && result.misp.count > 0) {
            plainText += `MISP:\n`;
            plainText += `  - Count: ${result.misp.count}\n`;
            if (result.misp.first_seen) plainText += `  - First Seen: ${result.misp.first_seen}\n`;
            if (result.misp.last_seen) plainText += `  - Last Seen: ${result.misp.last_seen}\n`;
            if (result.misp.link) plainText += `  - Link: ${result.misp.link}\n`;
            if (result.misp.events && result.misp.events.length > 0) {
                plainText += `  - Events:\n`;
                result.misp.events.forEach(event => {
                    plainText += `    - ${event.title}: ${event.url}\n`;
                });
            }
        }

        if (result.criminalip) {
            plainText += `Criminal IP:\n`;
            plainText += `  - Abuse Record Count: ${result.criminalip.abuse_record_count}\n`;
            if (result.criminalip.score) {
                plainText += `  - Score:\n`;
                plainText += `    - Inbound: ${result.criminalip.score.inbound}\n`;
                plainText += `    - Outbound: ${result.criminalip.score.outbound}\n`;
            }
            if (result.criminalip.current_open_port && result.criminalip.current_open_port.count > 0) {
                plainText += `  - Current Open Ports:\n`;
                result.criminalip.current_open_port.forEach(port => {
                    plainText += `    - ${port}\n`;
                });
            }
            if (result.criminalip.issues) {
                for (const [issue_name, value] of Object.entries(result.criminalip.issues)) {
                    plainText += `    - ${issue_name}: ${value}\n`;
                }
            }
            if (result.criminalip.represenative_domain) {
                plainText += `  - Representative Domain: ${result.criminalip.represenative_domain}\n`;
            }
        }

        if (result.alienvault) {
            plainText += `Alienvault:\n`;
            plainText += `  - Pulse Count: ${result.alienvault.count}\n`;
            if (result.alienvault.count > 0) {
                result.alienvault.pulses.forEach(alienvaultPulse => {
                    plainText += `  - ${alienvaultPulse.title}: ${alienvaultPulse.url}\n`;
                });
            }
            if (result.alienvault.malware_families.length > 0) {
                plainText += `  - Malware Families: ${result.alienvault.malware_families.join(', ')}\n`;
            }
            if (result.alienvault.adversary.length > 0) {
                plainText += `  - Adversary: ${result.alienvault.adversary.join(', ')}\n`;
            }

        }

        if (result.hudsonrock) {
            plainText += `Hudson Rock:\n`;

            if (result.type === "Email" && result.hudsonrock.stealers) {
                plainText += `Compromised Computer Details:\n`;
                result.hudsonrock.stealers.forEach(stealer => {
                    if (stealer.computer_name) plainText += `Computer Name: ${stealer.computer_name}\n`;
                    if (stealer.operating_system) plainText += `Operating System: ${stealer.operating_system}\n`;
                    if (stealer.date_compromised) plainText += `Date Compromised: ${stealer.date_compromised}\n`;
                    if (stealer.total_corporate_services) plainText += `Total Corporate Services: ${stealer.total_corporate_services}\n`;
                    if (stealer.total_user_services) plainText += `Total User Services: ${stealer.total_user_services}\n`;
                });
            } else if (result.type === "URL" || result.type === "FQDN") {
                plainText += `Compromised domain details:\n`;
                if (result.hudsonrock.total) plainText += `Total: ${result.hudsonrock.total}\n`;
                if (result.hudsonrock.totalStealers) plainText += `Total Stealers: ${result.hudsonrock.totalStealers}\n`;
                if (result.hudsonrock.employees) plainText += `Employees: ${result.hudsonrock.employees}\n`;
                if (result.hudsonrock.users) plainText += `Users: ${result.hudsonrock.users}\n`;
                if (result.hudsonrock.third_parties) plainText += `Third Parties: ${result.hudsonrock.third_parties}\n`;
                if (result.hudsonrock.totalUrls) plainText += `Total URLs: ${result.hudsonrock.totalUrls}\n`;
                if (result.hudsonrock.last_employee_compromised) plainText += `Last Employee Compromised: ${result.hudsonrock.last_employee_compromised.split('T')[0]}\n`;
                if (result.hudsonrock.last_user_compromised) plainText += `Last User Compromised: ${result.hudsonrock.last_user_compromised.split('T')[0]}\n`;
                if (result.hudsonrock.is_shopify) plainText += `Is Shopify: ${result.hudsonrock.is_shopify}\n`;
                if (result.hudsonrock.applications) plainText += `Applications: ${result.hudsonrock.applications.map(app => app.keyword).join(', ')}\n`;
                if (result.hudsonrock.stealerFamilies) {
                    plainText += `Stealer Families:\n`;
                    for (const [family, count] of Object.entries(result.hudsonrock.stealerFamilies)) {
                        plainText += `  - ${family}: ${count}\n`;
                    }
                }
                if (result.hudsonrock.stats.employees_urls) {
                    plainText += `Employee URLs:\n`;
                    result.hudsonrock.stats.employees_urls.forEach(url => {
                        if (!url.includes("••")) plainText += `  - ${url}\n`;
                    });
                }
                if (result.hudsonrock.stats.clients_urls) {
                    plainText += `Client URLs:\n`;
                    result.hudsonrock.stats.clients_urls.forEach(url => {
                        if (!url.includes("••")) plainText += `  - ${url}\n`;
                    });
                }
            }
        }

        if (result.crowdstrike) {
            plainText += `CrowdStrike:\n`;
            plainText += `  - Device Count: ${result.crowdstrike.device_count}\n`;
            if (result.crowdstrike.indicator_found) {
                plainText += `  - Published Date: ${result.crowdstrike.published_date}\n`;
                plainText += `  - Last Updated: ${result.crowdstrike.last_updated}\n`;
                if (result.crowdstrike.actors.length > 0) {
                    plainText += `  - Actors: ${result.crowdstrike.actors.join(', ')}\n`;
                }
                if (result.crowdstrike.malicious_confidence) {
                    plainText += `  - Malicious Confidence: ${result.crowdstrike.malicious_confidence}\n`;
                }
                if (result.crowdstrike.threat_types.length > 0) {
                    plainText += `  - Threat Types: ${result.crowdstrike.threat_types.join(', ')}\n`;
                }
                if (result.crowdstrike.malware_families.length > 0) {
                    plainText += `  - Malware Families: ${result.crowdstrike.malware_families.join(', ')}\n`;
                }
                if (result.crowdstrike.kill_chain.length > 0) {
                    plainText += `  - Kill Chain: ${result.crowdstrike.kill_chain.join(', ')}\n`;
                }
                if (result.crowdstrike.vulnerabilities.length > 0) {
                    plainText += `  - Vulnerabilities: ${result.crowdstrike.vulnerabilities.join(', ')}\n`;
                }
            }
        }

        if (result.crtsh && result.crtsh.top_domains && result.crtsh.top_domains.length > 0) {
            plainText += `crt.sh:\n`;
            result.crtsh.top_domains.forEach(domain => {
                plainText += `  - ${domain.domain} (${domain.count})\n`;
            });
            if (result.crtsh.link) {
                plainText += `  - Link: ${result.crtsh.link}\n`;
            }
        }
        plainText += '\n';
    });

    return plainText
}

function copyAsPlainText() {
    fetchResults()
        .then(data => {
            const plainText = formatResults(data);
            return navigator.clipboard.writeText(plainText);
        })
        .then(() => {
            const copyButton = document.querySelector('.btn[onclick="copyAsPlainText()"]');
            const initialBackgroundColor = copyButton.style.backgroundColor;
            const initialTextContent = copyButton.textContent;

            copyButton.style.backgroundColor = 'green';
            copyButton.textContent = 'Copied!';

            setTimeout(() => {
                copyButton.style.backgroundColor = initialBackgroundColor;
                copyButton.textContent = initialTextContent;
            }, 1000);
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
        });
}

function formatDefanged(plainText) {
    return plainText
        .replace(/\./g, '[.]')
        .replace(/@/g, '[@]')
        .replace(/:\/\//g, '[://]');
}

function copyAsDefanged() {
    fetchResults()
        .then(data => {
            const plainText = formatResults(data);
            const defangedText = formatDefanged(plainText);
            return navigator.clipboard.writeText(defangedText);
        })
        .then(() => {
            const copyButton = document.querySelector('.btn[onclick="copyAsDefanged()"]');
            const initialBackgroundColor = copyButton.style.backgroundColor;
            const initialTextContent = copyButton.textContent;

            copyButton.style.backgroundColor = 'green';
            copyButton.textContent = 'Defanged and Copied!';

            setTimeout(() => {
                copyButton.style.backgroundColor = initialBackgroundColor;
                copyButton.textContent = initialTextContent;
            }, 1000);
        })
        .catch(err => {
            console.error('Failed to copy defanged text: ', err);
        });
}
