#include "discovery.h"

/*
struct iface_info {
	ULONG ifIndex;
	std::string name;
	std::string description;
	uint8_t mac[6];
	uint8_t ip[4];
	uint8_t prefixlen;
	uint8_t gateway[4];
};

std::vector<iface_info> find_ifaces() {
	int i = 0;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	std::unordered_set<std::string> pcap_ifaces;
	for (pcap_if_t *d = alldevs; d; d = d->next) {
		pcap_ifaces.insert(d->name);
	}
	pcap_freealldevs(alldevs);

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
	ULONG size = 10 * 1024;
	std::vector<uint8_t> buf(size);
	ULONG res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES *)&buf[0], &size);
	if (res == ERROR_BUFFER_OVERFLOW) {
		buf.resize(size);
		res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES *)&buf[0], &size);
	}
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Can't get list of adapters: %d\n", res);
		exit(1);
	}

	std::vector<iface_info> ifaces;
	IP_ADAPTER_ADDRESSES *p = (IP_ADAPTER_ADDRESSES *)&buf[0];
	for (; p; p = p->Next) {
		if (pcap_ifaces.count(std::string("\\Device\\NPF_") + p->AdapterName) == 0) {
			continue;
		}
		if (p->OperStatus != IfOperStatusUp) {
			continue;
		}
		iface_info ii{};
		ii.ifIndex = p->IfIndex;
		ii.name = std::string("\\Device\\NPF_") + p->AdapterName;
		ii.description = unicode_to_str(p->Description) + " (" + unicode_to_str(p->FriendlyName) + ")";
		memcpy(ii.mac, p->PhysicalAddress, 6);
		if (p->FirstUnicastAddress) {
			memcpy(ii.ip, &((sockaddr_in *)p->FirstUnicastAddress->Address.lpSockaddr)->sin_addr, 4);
			ii.prefixlen = p->FirstUnicastAddress->OnLinkPrefixLength;
		}
		if (p->FirstGatewayAddress) {
			memcpy(ii.gateway, &((sockaddr_in *)p->FirstGatewayAddress->Address.lpSockaddr)->sin_addr, 4);
		}
		ifaces.push_back(std::move(ii));
	}
	return ifaces;
}

void print_ifaces(const std::vector<iface_info>& ifaces) {
	int i = 1;
	for (const iface_info& iface : ifaces) {
		printf("%d. %s\t%s\n\t%s/%d gw=%s\n", i, iface.name.c_str(), iface.description.c_str(),
			ip_to_str(iface.ip).c_str(), iface.prefixlen, ip_to_str(iface.gateway).c_str());
		i++;
	}
}
*/
