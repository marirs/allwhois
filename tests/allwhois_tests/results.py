"""Results."""

lookup_results = {
    'nonexistant_tld': {'domain_name': 'nonexistant.tld', 'msg': 'Err parsing', 'z_raw': 'No whois server is known for this kind of object.\n'},
    'example_com': {'domain_info': {'name': 'EXAMPLE.COM', 'updated_date': '2019-08-14T07:04:41', 'created_date': '1992-01-01T00:00:00', 'expiry_date': '2020-08-13T04:00:00', 'status': ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'], 'name_servers': ['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET'], 'dnssec': 'signedDelegation', 'dnssec_ds_data': ['31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE', '31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C', '43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083', '43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997EDF96A918', '31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142', '31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D8F6B916D']}, 'registry_info': {'domain_id': '2336799_DOMAIN_COM-VRSN'}, 'registrar_info': {'whois_server': 'whois.iana.org', 'url': 'http://res-dom.iana.org', 'name': 'RESERVED-Internet Assigned Numbers Authority', 'iana_id': '376', 'abuse_contact_email': '', 'abuse_contact_phone': ''}, 'organisation': 'Internet Assigned Numbers Authority', 'msg': 'success', 'z_raw': "   Domain Name: EXAMPLE.COM\n   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.iana.org\n   Registrar URL: http://res-dom.iana.org\n   Updated Date: 2019-08-14T07:04:41Z\n   Creation Date: 1995-08-14T04:00:00Z\n   Registry Expiry Date: 2020-08-13T04:00:00Z\n   Registrar: RESERVED-Internet Assigned Numbers Authority\n   Registrar IANA ID: 376\n   Registrar Abuse Contact Email:\n   Registrar Abuse Contact Phone:\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Name Server: A.IANA-SERVERS.NET\n   Name Server: B.IANA-SERVERS.NET\n   DNSSEC: signedDelegation\n   DNSSEC DS Data: 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE\n   DNSSEC DS Data: 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C\n   DNSSEC DS Data: 43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083\n   DNSSEC DS Data: 43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997EDF96A918\n   DNSSEC DS Data: 31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142\n   DNSSEC DS Data: 31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D8F6B916D\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2020-08-03T03:51:47Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\n% IANA WHOIS server\n% for more information on IANA, visit http://www.iana.org\n% This query returned 1 object\n\ndomain:       EXAMPLE.COM\n\norganisation: Internet Assigned Numbers Authority\n\ncreated:      1992-01-01\nsource:       IANA\n\n"},
    'google_com': {'domain_info': {'name': 'GOOGLE.COM', 'updated_date': '2019-09-09T08:39:04-07:00', 'created_date': '1997-09-15T00:00:00-07:00', 'expiry_date': '2028-09-14T04:00:00', 'status': ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited', 'serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'], 'name_servers': ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM'], 'dnssec': 'unsigned'}, 'registry_info': {'domain_id': '2138514_DOMAIN_COM-VRSN'}, 'registrar_info': {'whois_server': 'whois.markmonitor.com', 'url': 'http://www.markmonitor.com', 'name': 'MarkMonitor Inc', 'iana_id': '292', 'abuse_contact_email': 'abusecomplaints@markmonitor.com', 'abuse_contact_phone': '+1.2083895740, +1.2083895770', 'registration_expiration_date': '2028-09-13T00:00:00-07:00'}, 'registrant_info': {'organization': 'Google LLC', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com', 'address': 'CA, US'}, 'admin_info': {'organization': 'Google LLC', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com', 'address': 'CA, US'}, 'tech_info': {'organization': 'Google LLC', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.com', 'address': 'CA, US'}, 'msg': 'success', 'z_raw': '   Domain Name: GOOGLE.COM\n   Registry Domain ID: 2138514_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2019-09-09T15:39:04Z\n   Creation Date: 1997-09-15T04:00:00Z\n   Registry Expiry Date: 2028-09-14T04:00:00Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2083895740\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS1.GOOGLE.COM\n   Name Server: NS2.GOOGLE.COM\n   Name Server: NS3.GOOGLE.COM\n   Name Server: NS4.GOOGLE.COM\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2020-08-03T03:38:42Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar\'s sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant\'s agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar\'s Whois database to\nview the registrar\'s reported date of expiration for this registration.\n\nDomain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2019-09-09T08:39:04-0700\nCreation Date: 1997-09-15T00:00:00-0700\nRegistrar Registration Expiration Date: 2028-09-13T00:00:00-0700\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895770\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Organization: Google LLC\nRegistrant State/Province: CA\nRegistrant Country: US\nRegistrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nAdmin Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nTech Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com\nName Server: ns3.google.com\nName Server: ns1.google.com\nName Server: ns4.google.com\nName Server: ns2.google.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2020-08-02T20:36:29-0700 <<<\n\nFor more information on WHOIS status codes, please visit:\n  https://www.icann.org/resources/pages/epp-status-codes\n\nIf you wish to contact this domain’s Registrant, Administrative, or Technical\ncontact, and such email address is not visible above, you may do so via our web\nform, pursuant to ICANN’s Temporary Specification. To verify that you are not a\nrobot, please enter your email address to receive a link to a page that\nfacilitates email communication with the relevant contact(s).\n\nWeb-based WHOIS:\n  https://domains.markmonitor.com/whois\n\nIf you have a legitimate interest in viewing the non-public WHOIS details, send\nyour request and the reasons for your request to whoisrequest@markmonitor.com\nand specify the domain name in the subject line. We will review that request and\nmay ask for supporting documentation and explanation.\n\nThe data in MarkMonitor’s WHOIS database is provided for information purposes,\nand to assist persons in obtaining information about or related to a domain\nname’s registration record. While MarkMonitor believes the data to be accurate,\nthe data is provided "as is" with no guarantee or warranties regarding its\naccuracy.\n\nBy submitting a WHOIS query, you agree that you will use this data only for\nlawful purposes and that, under no circumstances will you use this data to:\n  (1) allow, enable, or otherwise support the transmission by email, telephone,\nor facsimile of mass, unsolicited, commercial advertising, or spam; or\n  (2) enable high volume, automated, or electronic processes that send queries,\ndata, or email to MarkMonitor (or its systems) or the domain name contacts (or\nits systems).\n\nMarkMonitor reserves the right to modify these terms at any time.\n\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor Domain Management(TM)\nProtecting companies and consumers in a digital world.\n\nVisit MarkMonitor at https://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n--\n'},
    'google_net': {'domain_info': {'name': 'GOOGLE.NET', 'updated_date': '2020-02-12T02:36:07-08:00', 'created_date': '1999-03-15T00:00:00-08:00', 'expiry_date': '2021-03-15T04:00:00', 'status': ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited', 'serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'], 'name_servers': ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM'], 'dnssec': 'unsigned'}, 'registry_info': {'domain_id': '4802712_DOMAIN_NET-VRSN'}, 'registrar_info': {'whois_server': 'whois.markmonitor.com', 'url': 'http://www.markmonitor.com', 'name': 'MarkMonitor Inc', 'iana_id': '292', 'abuse_contact_email': 'abusecomplaints@markmonitor.com', 'abuse_contact_phone': '+1.2083895740, +1.2083895770', 'registration_expiration_date': '2021-03-13T23:00:00-08:00'}, 'registrant_info': {'organization': 'Google Inc', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.net', 'address': 'CA, US'}, 'admin_info': {'organization': 'Google Inc', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.net', 'address': 'CA, US'}, 'tech_info': {'organization': 'Google Inc', 'state_province': 'CA', 'country': 'US', 'email': 'Select Request Email Form at https://domains.markmonitor.com/whois/google.net', 'address': 'CA, US'}, 'msg': 'success', 'z_raw': '   Domain Name: GOOGLE.NET\n   Registry Domain ID: 4802712_DOMAIN_NET-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2020-02-12T10:36:07Z\n   Creation Date: 1999-03-15T05:00:00Z\n   Registry Expiry Date: 2021-03-15T04:00:00Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2083895740\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS1.GOOGLE.COM\n   Name Server: NS2.GOOGLE.COM\n   Name Server: NS3.GOOGLE.COM\n   Name Server: NS4.GOOGLE.COM\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2020-08-01T07:25:37Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar\'s sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant\'s agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar\'s Whois database to\nview the registrar\'s reported date of expiration for this registration.\n\nDomain Name: google.net\nRegistry Domain ID: 4802712_DOMAIN_NET-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2020-02-12T02:36:07-0800\nCreation Date: 1999-03-15T00:00:00-0800\nRegistrar Registration Expiration Date: 2021-03-13T23:00:00-0800\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895770\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Organization: Google Inc.\nRegistrant State/Province: CA\nRegistrant Country: US\nRegistrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.net\nAdmin Organization: Google Inc.\nAdmin State/Province: CA\nAdmin Country: US\nAdmin Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.net\nTech Organization: Google Inc.\nTech State/Province: CA\nTech Country: US\nTech Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.net\nName Server: ns1.google.com\nName Server: ns4.google.com\nName Server: ns2.google.com\nName Server: ns3.google.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2020-08-01T00:25:51-0700 <<<\n\nFor more information on WHOIS status codes, please visit:\n  https://www.icann.org/resources/pages/epp-status-codes\n\nIf you wish to contact this domain’s Registrant, Administrative, or Technical\ncontact, and such email address is not visible above, you may do so via our web\nform, pursuant to ICANN’s Temporary Specification. To verify that you are not a\nrobot, please enter your email address to receive a link to a page that\nfacilitates email communication with the relevant contact(s).\n\nWeb-based WHOIS:\n  https://domains.markmonitor.com/whois\n\nIf you have a legitimate interest in viewing the non-public WHOIS details, send\nyour request and the reasons for your request to whoisrequest@markmonitor.com\nand specify the domain name in the subject line. We will review that request and\nmay ask for supporting documentation and explanation.\n\nThe data in MarkMonitor’s WHOIS database is provided for information purposes,\nand to assist persons in obtaining information about or related to a domain\nname’s registration record. While MarkMonitor believes the data to be accurate,\nthe data is provided "as is" with no guarantee or warranties regarding its\naccuracy.\n\nBy submitting a WHOIS query, you agree that you will use this data only for\nlawful purposes and that, under no circumstances will you use this data to:\n  (1) allow, enable, or otherwise support the transmission by email, telephone,\nor facsimile of mass, unsolicited, commercial advertising, or spam; or\n  (2) enable high volume, automated, or electronic processes that send queries,\ndata, or email to MarkMonitor (or its systems) or the domain name contacts (or\nits systems).\n\nMarkMonitor reserves the right to modify these terms at any time.\n\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor Domain Management(TM)\nProtecting companies and consumers in a digital world.\n\nVisit MarkMonitor at https://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n\n'},
    'google_org': {'domain_info': {'name': 'GOOGLE.ORG', 'updated_date': '2019-09-18T09:31:16', 'created_date': '1998-10-21T04:00:00', 'expiry_date': '2020-10-20T04:00:00', 'status': ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited', 'serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'], 'name_servers': ['NS2.GOOGLE.COM', 'NS1.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM'], 'dnssec': 'unsigned'}, 'registry_info': {'domain_id': 'D2244233-LROR'}, 'registrar_info': {'whois_server': 'whois.markmonitor.com', 'url': 'http://www.markmonitor.com', 'registration_expiration_date': '', 'name': 'MarkMonitor Inc', 'iana_id': '292', 'abuse_contact_email': 'abusecomplaints@markmonitor.com', 'abuse_contact_phone': '+1.2083895740'}, 'registrant_info': {'organization': 'Google Inc', 'state_province': 'CA', 'country': 'US', 'address': 'CA, US'}, 'msg': 'success', 'z_raw': 'Domain Name: GOOGLE.ORG\nRegistry Domain ID: D2244233-LROR\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2019-09-18T09:31:16Z\nCreation Date: 1998-10-21T04:00:00Z\nRegistry Expiry Date: 2020-10-20T04:00:00Z\nRegistrar Registration Expiration Date:\nRegistrar: MarkMonitor Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nReseller:\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nRegistrant Organization: Google Inc.\nRegistrant State/Province: CA\nRegistrant Country: US\nName Server: NS2.GOOGLE.COM\nName Server: NS1.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nDNSSEC: unsigned\nURL of the ICANN Whois Inaccuracy Complaint Form https://www.icann.org/wicf/)\n>>> Last update of WHOIS database: 2020-08-01T07:24:52Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\n'},

}
