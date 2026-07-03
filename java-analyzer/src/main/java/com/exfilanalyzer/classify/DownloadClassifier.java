package com.exfilanalyzer.classify;

import com.exfilanalyzer.correlate.CorrelatedRun;
import com.exfilanalyzer.correlate.EgressEvent;
import com.exfilanalyzer.ingest.DnsEvent;
import com.exfilanalyzer.ingest.HttpEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class DownloadClassifier {
    private static final Pattern IPV4 = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9a-fA-F:]+$");
    private static final String RESOURCE_ROOT = "/com/exfilanalyzer/classify/";

    private final Map<String, DomainList> domainLists;

    private DownloadClassifier(Map<String, DomainList> domainLists) {
        this.domainLists = Map.copyOf(domainLists);
    }

    public static DownloadClassifier loadDefault() {
        return new DownloadClassifier(Map.of(
                "url_shortener", loadDomainList("url-shorteners.txt"),
                "ephemeral_domain", loadDomainList("ephemeral-domains.txt"),
                "exfil_service", loadDomainList("exfil-services.txt"),
                "intel_lookup", loadDomainList("intel-domains.txt"),
                "malware_download", loadDomainList("malware-download-domains.txt")));
    }

    public ClassificationResult classify(
            CorrelatedRun run, List<HttpEvent> httpEvents, List<DnsEvent> dnsEvents) {
        List<HttpEvent> runHttp = httpEvents.stream()
                .filter(event -> run.runId().equals(event.runId()))
                .toList();
        List<DnsEvent> runDns = dnsEvents.stream()
                .filter(event -> run.runId().equals(event.runId()))
                .toList();
        List<ClassifiedEgress> classified = run.egressEvents().stream()
                .map(egress -> classifyOne(egress, runHttp, runDns))
                .toList();
        return new ClassificationResult(run.runId(), classified);
    }

    public boolean isListedDomain(String host) {
        return domainLists.values().stream().anyMatch(list -> list.matches(host));
    }

    private ClassifiedEgress classifyOne(
            EgressEvent egress, List<HttpEvent> httpEvents, List<DnsEvent> dnsEvents) {
        LinkedHashSet<String> reasons = new LinkedHashSet<>();
        boolean confirmed = false;

        if (!egress.canaryMatch().isEmpty()) {
            confirmed = true;
            reasons.add("canary_match");
        }

        if (matchingDnsCanary(egress, dnsEvents)) {
            confirmed = true;
            reasons.add("dns_exfil");
            reasons.add("dns_canary_match");
        }

        String destination = destination(egress);
        if (destination == null) {
            reasons.add("unknown_destination");
        } else {
            addDomainReasons(egress, reasons);
            if (isRawIpDestination(egress)) {
                reasons.add("raw_ip");
            }
            if (looksLikeDnsSubdomainExfil(destination, dnsEvents)) {
                reasons.add("dns_exfil");
            }
            if (isHighEntropyDomain(destination)) {
                reasons.add("high_entropy_domain");
            }
        }

        DownloadState state = downloadState(egress, httpEvents);
        if (state == DownloadState.OBSERVED) {
            reasons.add("synthetic_honeynet_response");
        }

        Disposition disposition;
        if (confirmed) {
            disposition = Disposition.EXFIL_CONFIRMED;
        } else {
            boolean suspicious = reasons.stream()
                    .anyMatch(reason -> !reason.equals("synthetic_honeynet_response"));
            if (suspicious) {
                disposition = Disposition.SUSPICIOUS;
            } else {
                disposition = Disposition.LEGIT_LOOKING;
                reasons.add("no_suspicious_signals");
            }
        }

        return new ClassifiedEgress(egress, disposition, state, List.copyOf(reasons));
    }

    private void addDomainReasons(EgressEvent egress, Set<String> reasons) {
        String candidate = domainRuleCandidate(egress);
        for (Map.Entry<String, DomainList> entry : domainLists.entrySet()) {
            if (entry.getValue().matches(candidate)) {
                reasons.add(entry.getKey());
            }
        }
    }

    private static DownloadState downloadState(EgressEvent egress, List<HttpEvent> httpEvents) {
        if (egress.flowId() == null) {
            return DownloadState.ATTEMPTED;
        }
        boolean observed = httpEvents.stream()
                .filter(event -> Objects.equals(event.flowId(), egress.flowId()))
                .anyMatch(event -> event.responseBodySha256() != null
                        && !event.responseBodySha256().isBlank());
        return observed ? DownloadState.OBSERVED : DownloadState.ATTEMPTED;
    }

    private static boolean matchingDnsCanary(EgressEvent egress, List<DnsEvent> dnsEvents) {
        return dnsEvents.stream()
                .filter(event -> !event.canaryMatch().isEmpty())
                .anyMatch(event -> dnsMatchesEgress(event.query(), egress.host()));
    }

    private static boolean looksLikeDnsSubdomainExfil(String host, List<DnsEvent> dnsEvents) {
        return dnsEvents.stream()
                .map(DnsEvent::query)
                .filter(query -> dnsMatchesEgress(query, host))
                .map(DownloadClassifier::firstLabel)
                .anyMatch(label -> label.length() >= 24 || highEntropyLabel(label));
    }

    private static boolean dnsMatchesEgress(String query, String host) {
        if (query == null || host == null || host.isBlank()) {
            return false;
        }
        String q = normalizeHost(query);
        String h = normalizeHost(host);
        return q.equals(h) || q.endsWith("." + h) || h.endsWith("." + q);
    }

    private static boolean isRawIpDestination(EgressEvent egress) {
        return (egress.host() == null || egress.host().isBlank()) && isIpLiteral(egress.dstIp());
    }

    private static String destination(EgressEvent egress) {
        if (egress.host() != null && !egress.host().isBlank()) {
            return egress.host();
        }
        if (isIpLiteral(egress.dstIp())) {
            return egress.dstIp();
        }
        return null;
    }

    private static String domainRuleCandidate(EgressEvent egress) {
        String host = egress.host() == null ? "" : egress.host();
        String path = egress.path() == null ? "" : egress.path();
        return host + path;
    }

    private static boolean isHighEntropyDomain(String host) {
        String normalized = normalizeHost(host);
        if (isIpLiteral(normalized)) {
            return false;
        }
        return highEntropyLabel(firstLabel(normalized));
    }

    private static boolean highEntropyLabel(String label) {
        if (label.length() < 16 || label.chars().noneMatch(Character::isDigit)) {
            return false;
        }
        return shannonEntropy(label) >= 3.4;
    }

    private static double shannonEntropy(String value) {
        Map<Integer, Long> counts = value.chars()
                .boxed()
                .collect(Collectors.groupingBy(ch -> ch, Collectors.counting()));
        double len = value.length();
        double entropy = 0.0;
        for (long count : counts.values()) {
            double p = count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private static String firstLabel(String host) {
        String normalized = normalizeHost(host);
        int dot = normalized.indexOf('.');
        return dot < 0 ? normalized : normalized.substring(0, dot);
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        if (IPV4.matcher(normalized).matches()) {
            String[] parts = normalized.split("\\.");
            for (String part : parts) {
                int octet = Integer.parseInt(part);
                if (octet > 255) {
                    return false;
                }
            }
            return true;
        }
        return normalized.contains(":") && IPV6_CHARS.matcher(normalized).matches();
    }

    private static String normalizeHost(String value) {
        String host = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (host.contains("://")) {
            host = URI.create(host).getHost();
        }
        if (host == null) {
            return "";
        }
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        int port = host.lastIndexOf(':');
        if (port > 0 && host.indexOf(':') == port) {
            host = host.substring(0, port);
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        return IDN.toASCII(host);
    }

    private static DomainList loadDomainList(String fileName) {
        String resource = RESOURCE_ROOT + fileName;
        try (InputStream stream = DownloadClassifier.class.getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalStateException("missing classifier resource: " + resource);
            }
            List<String> entries = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                        entries.add(trimmed.toLowerCase(Locale.ROOT));
                    }
                }
            }
            return new DomainList(entries);
        } catch (IOException ex) {
            throw new IllegalStateException("could not load classifier resource: " + resource, ex);
        }
    }

    private record DomainList(List<String> entries) {
        private DomainList {
            entries = List.copyOf(entries);
        }

        private boolean matches(String candidate) {
            String raw = candidate == null ? "" : candidate.trim().toLowerCase(Locale.ROOT);
            String normalized = normalizeHost(candidate);
            for (String entry : entries) {
                if (entry.contains("/")) {
                    if (raw.equals(entry)
                            || raw.startsWith(entry + "/")
                            || raw.contains("://" + entry)
                            || raw.contains("://" + entry + "/")) {
                        return true;
                    }
                    continue;
                }
                if (normalized.equals(entry) || normalized.endsWith("." + entry)) {
                    return true;
                }
            }
            return false;
        }
    }
}
