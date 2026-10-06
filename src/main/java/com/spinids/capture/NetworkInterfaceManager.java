package com.spinids.capture;

import com.spinids.api.dto.NetworkInterfaceDto;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.*;

/**
 * Discovers and inspects physical and virtual network interfaces using Pcap4J and Npcap.
 *
 * <p>Identifies active Wi-Fi, Ethernet, and virtual adapters, parses their IPv4/IPv6 addresses,
 * hardware MAC addresses, and operational statuses, and provides intelligent recommendations
 * without hardcoding or blindly assuming interface indices.</p>
 */
public class NetworkInterfaceManager {

    static {
        // Automatically configure Npcap library path on Windows if available
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            String npcapPath = "C:\\Windows\\System32\\Npcap";
            if (new File(npcapPath).exists()) {
                String current = System.getProperty("jna.library.path");
                if (current == null || current.isEmpty()) {
                    System.setProperty("jna.library.path", npcapPath);
                } else if (!current.contains(npcapPath)) {
                    System.setProperty("jna.library.path", current + ";" + npcapPath);
                }
            }
        }
    }

    private static volatile NetworkInterfaceManager instance;

    public static NetworkInterfaceManager getInstance() {
        if (instance == null) {
            synchronized (NetworkInterfaceManager.class) {
                if (instance == null) {
                    instance = new NetworkInterfaceManager();
                }
            }
        }
        return instance;
    }

    public NetworkInterfaceManager() {}

    /**
     * Retrieves the raw list of PcapNetworkInterface objects detected by Pcap4J.
     *
     * @return list of PcapNetworkInterface, never null
     */
    public List<PcapNetworkInterface> getAllNetworkInterfaces() {
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            return allDevs != null ? allDevs : Collections.emptyList();
        } catch (PcapNativeException e) {
            System.err.println("[-] Warning: Failed to query network interfaces: " + e.getMessage());
            return Collections.emptyList();
        } catch (Throwable t) {
            System.err.println("[-] Warning: Npcap / Pcap4J error discovering interfaces: " + t.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Converts all detected network interfaces into structured DTOs suitable for REST responses.
     *
     * @return list of NetworkInterfaceDto
     */
    public List<NetworkInterfaceDto> getInterfaceDtos() {
        List<PcapNetworkInterface> devs = getAllNetworkInterfaces();
        List<NetworkInterfaceDto> dtos = new ArrayList<>();

        for (PcapNetworkInterface dev : devs) {
            dtos.add(toDto(dev));
        }

        // Sort: recommended first, then active/up, then others
        dtos.sort((a, b) -> {
            if (a.isRecommended() != b.isRecommended()) {
                return a.isRecommended() ? -1 : 1;
            }
            if (a.isUp() != b.isUp()) {
                return a.isUp() ? -1 : 1;
            }
            if (a.isLoopback() != b.isLoopback()) {
                return a.isLoopback() ? 1 : -1;
            }
            return a.getDisplayName().compareToIgnoreCase(b.getDisplayName());
        });

        return dtos;
    }

    /**
     * Finds a PcapNetworkInterface matching the given name or description.
     *
     * @param name exact system name (e.g. "\\Device\\NPF_{...}") or friendly name substring
     * @return the matching PcapNetworkInterface, or null if not found
     */
    public PcapNetworkInterface getInterfaceByName(String name) {
        if (name == null || name.trim().isEmpty()) return null;
        String query = name.trim();

        List<PcapNetworkInterface> devs = getAllNetworkInterfaces();
        // 1. Exact match on getName()
        for (PcapNetworkInterface dev : devs) {
            if (dev.getName().equalsIgnoreCase(query)) {
                return dev;
            }
        }

        // 2. Substring or description match
        for (PcapNetworkInterface dev : devs) {
            String desc = dev.getDescription() != null ? dev.getDescription() : "";
            if (desc.equalsIgnoreCase(query) || desc.toLowerCase().contains(query.toLowerCase())
                    || dev.getName().toLowerCase().contains(query.toLowerCase())) {
                return dev;
            }
        }

        return null;
    }

    /**
     * Determines the optimal default interface to monitor.
     * Prefers active non-loopback interfaces carrying non-APIPA (non-169.254) IPv4 traffic.
     *
     * @return the recommended default PcapNetworkInterface, or null if no interfaces exist
     */
    public PcapNetworkInterface getDefaultInterface() {
        List<PcapNetworkInterface> devs = getAllNetworkInterfaces();
        if (devs.isEmpty()) return null;

        // Pass 1: Active, non-loopback with valid routable IPv4 (e.g., 10.x, 192.168.x, 172.16-31.x)
        for (PcapNetworkInterface dev : devs) {
            if (dev.isLoopBack() || !dev.isUp()) continue;

            List<String> ipv4List = extractIpv4(dev);
            for (String ip : ipv4List) {
                if (!ip.startsWith("169.254.") && !ip.startsWith("127.")) {
                    return dev;
                }
            }
        }

        // Pass 2: Active, non-loopback with any IPv4
        for (PcapNetworkInterface dev : devs) {
            if (dev.isLoopBack() || !dev.isUp()) continue;
            if (!extractIpv4(dev).isEmpty()) {
                return dev;
            }
        }

        // Pass 3: Any non-loopback interface
        for (PcapNetworkInterface dev : devs) {
            if (!dev.isLoopBack()) {
                return dev;
            }
        }

        // Fallback: First interface in list (e.g. loopback)
        return devs.get(0);
    }

    /**
     * Converts a PcapNetworkInterface to a NetworkInterfaceDto.
     */
    public NetworkInterfaceDto toDto(PcapNetworkInterface dev) {
        String name = dev.getName();
        String desc = dev.getDescription() != null ? dev.getDescription() : "Generic Network Interface";
        String displayName = generateFriendlyName(dev);

        List<String> allAddrs = new ArrayList<>();
        List<String> ipv4List = new ArrayList<>();
        List<String> ipv6List = new ArrayList<>();

        if (dev.getAddresses() != null) {
            for (PcapAddress addr : dev.getAddresses()) {
                InetAddress inet = addr.getAddress();
                if (inet != null) {
                    String ipStr = inet.getHostAddress();
                    if (ipStr.contains("%")) {
                        ipStr = ipStr.substring(0, ipStr.indexOf("%"));
                    }
                    allAddrs.add(ipStr);
                    if (inet instanceof Inet4Address) {
                        ipv4List.add(ipStr);
                    } else if (inet instanceof Inet6Address) {
                        ipv6List.add(ipStr);
                    }
                }
            }
        }

        String mac = null;
        if (dev.getLinkLayerAddresses() != null && !dev.getLinkLayerAddresses().isEmpty()) {
            LinkLayerAddress lla = dev.getLinkLayerAddresses().get(0);
            if (lla != null) {
                mac = lla.toString();
            }
        }

        boolean loopback = dev.isLoopBack();
        boolean up = dev.isUp();

        // An interface is recommended if it is UP, non-loopback, and possesses a routable IPv4 address
        boolean recommended = !loopback && up && ipv4List.stream().anyMatch(ip -> !ip.startsWith("169.254.") && !ip.startsWith("127."));

        return new NetworkInterfaceDto(
                name,
                displayName,
                desc,
                allAddrs,
                ipv4List,
                ipv6List,
                mac,
                loopback,
                up,
                recommended
        );
    }

    private List<String> extractIpv4(PcapNetworkInterface dev) {
        List<String> list = new ArrayList<>();
        if (dev.getAddresses() != null) {
            for (PcapAddress addr : dev.getAddresses()) {
                if (addr.getAddress() instanceof Inet4Address) {
                    list.add(addr.getAddress().getHostAddress());
                }
            }
        }
        return list;
    }

    private String generateFriendlyName(PcapNetworkInterface dev) {
        String desc = dev.getDescription() != null ? dev.getDescription() : "";
        String descLower = desc.toLowerCase();

        if (dev.isLoopBack() || descLower.contains("loopback")) {
            return "Loopback Adapter";
        }
        if (descLower.contains("wi-fi") || descLower.contains("wireless") || descLower.contains("wlan") || descLower.contains("802.11")) {
            return "Wi-Fi — " + desc;
        }
        if (descLower.contains("ethernet") || descLower.contains("gigabit") || descLower.contains("gbe") || descLower.contains("lan")) {
            return "Ethernet — " + desc;
        }
        if (descLower.contains("bluetooth")) {
            return "Bluetooth PAN — " + desc;
        }
        if (descLower.contains("hyper-v") || descLower.contains("virtual") || descLower.contains("vmware") || descLower.contains("tap")) {
            return "Virtual Adapter — " + desc;
        }

        return desc.isEmpty() ? dev.getName() : desc;
    }
}
