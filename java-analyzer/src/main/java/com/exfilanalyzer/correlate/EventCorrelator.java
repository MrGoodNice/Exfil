package com.exfilanalyzer.correlate;

import com.exfilanalyzer.ingest.FileEvent;
import com.exfilanalyzer.ingest.HttpEvent;
import com.exfilanalyzer.ingest.NetworkEvent;
import com.exfilanalyzer.ingest.ProcEvent;
import com.exfilanalyzer.ingest.RunEvents;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class EventCorrelator {
    private static final Duration JOIN_WINDOW = Duration.ofSeconds(5);

    public AnalysisResult correlate(RunEvents events) {
        List<CorrelatedRun> runs = new ArrayList<>();
        for (String runId : runIds(events)) {
            runs.add(correlateRun(runId, events));
        }
        runs.sort(Comparator.comparing(CorrelatedRun::runId));
        return new AnalysisResult(runs, events.parseErrors());
    }

    private CorrelatedRun correlateRun(String runId, RunEvents events) {
        List<NetworkEvent> network = events.network().stream()
                .filter(event -> runId.equals(event.runId()))
                .sorted(Comparator.comparing((NetworkEvent event) -> instant(event.ts())))
                .toList();
        List<HttpEvent> http = events.http().stream()
                .filter(event -> runId.equals(event.runId()))
                .sorted(Comparator.comparing((HttpEvent event) -> instant(event.ts())))
                .toList();
        List<FileEvent> files = events.files().stream()
                .filter(event -> runId.equals(event.runId()))
                .toList();
        List<ProcEvent> proc = events.proc().stream()
                .filter(event -> runId.equals(event.runId()))
                .toList();

        Map<String, List<HttpEvent>> httpByFlow = new LinkedHashMap<>();
        for (HttpEvent event : http) {
            if (event.flowId() != null) {
                httpByFlow.computeIfAbsent(event.flowId(), ignored -> new ArrayList<>()).add(event);
            }
        }

        List<NetworkEvent> ayaEvents = network.stream()
                .filter(event -> "aya_connect".equals(event.source()))
                .toList();
        Set<NetworkEvent> usedAya = new HashSet<>();
        List<EgressEvent> egress = new ArrayList<>();

        for (NetworkEvent honeynet : network.stream()
                .filter(event -> "honeynet".equals(event.source()))
                .toList()) {
            Optional<NetworkEvent> aya = bestAyaMatch(honeynet, ayaEvents, usedAya);
            aya.ifPresent(usedAya::add);
            List<HttpEvent> httpEvents = httpByFlow.getOrDefault(honeynet.flowId(), List.of());
            if (httpEvents.isEmpty()) {
                egress.add(fromNetworkPair(runId, honeynet, aya.orElse(null), null));
            } else {
                for (HttpEvent httpEvent : httpEvents) {
                    egress.add(fromNetworkPair(runId, honeynet, aya.orElse(null), httpEvent));
                }
            }
        }

        for (NetworkEvent aya : ayaEvents) {
            if (!usedAya.contains(aya)) {
                egress.add(fromAyaOnly(runId, aya));
            }
        }

        egress.sort(Comparator.comparing((EgressEvent event) -> instant(event.ts())));
        Set<String> touchedCanaries = touchedCanaries(files);
        Set<String> matchedCanaries = matchedCanaries(egress);
        List<EvidenceChain> chains = evidenceChains(runId, files, proc, egress);

        return new CorrelatedRun(runId, egress, chains, touchedCanaries, matchedCanaries);
    }

    private static Optional<NetworkEvent> bestAyaMatch(
            NetworkEvent honeynet, List<NetworkEvent> ayaEvents, Set<NetworkEvent> usedAya) {
        return ayaEvents.stream()
                .filter(event -> !usedAya.contains(event))
                .filter(event -> sameDestination(event, honeynet))
                .filter(event -> protoCompatible(event.proto(), honeynet.proto()))
                .filter(event -> !instant(event.ts()).isAfter(instant(honeynet.ts())))
                .filter(event -> Duration.between(instant(event.ts()), instant(honeynet.ts()))
                        .compareTo(JOIN_WINDOW)
                        <= 0)
                .max(Comparator.comparing((NetworkEvent event) -> instant(event.ts())));
    }

    private static EgressEvent fromNetworkPair(
            String runId, NetworkEvent honeynet, NetworkEvent aya, HttpEvent http) {
        Integer pid = aya == null ? honeynet.pid() : aya.pid();
        return new EgressEvent(
                runId,
                honeynet.sampleId(),
                honeynet.ts(),
                honeynet.dstIp(),
                honeynet.dstPort(),
                honeynet.proto(),
                pid,
                http == null ? null : http.host(),
                http == null ? null : http.path(),
                http == null ? List.of() : http.canaryMatch(),
                honeynet.flowId(),
                aya != null,
                false,
                aya == null);
    }

    private static EgressEvent fromAyaOnly(String runId, NetworkEvent aya) {
        return new EgressEvent(
                runId,
                aya.sampleId(),
                aya.ts(),
                aya.dstIp(),
                aya.dstPort(),
                aya.proto(),
                aya.pid(),
                null,
                null,
                List.of(),
                null,
                false,
                true,
                false);
    }

    private static Set<String> touchedCanaries(List<FileEvent> files) {
        Set<String> paths = new LinkedHashSet<>();
        for (FileEvent event : files) {
            if (event.isCanary()) {
                paths.add(event.path());
            }
        }
        return paths;
    }

    private static Set<String> matchedCanaries(List<EgressEvent> egress) {
        Set<String> ids = new LinkedHashSet<>();
        for (EgressEvent event : egress) {
            ids.addAll(event.canaryMatch());
        }
        return ids;
    }

    private static List<EvidenceChain> evidenceChains(
            String runId, List<FileEvent> files, List<ProcEvent> proc, List<EgressEvent> egress) {
        Map<Integer, Integer> parentByPid = parentByPid(proc);
        List<EvidenceChain> chains = new ArrayList<>();
        for (FileEvent file : files) {
            if (!file.isCanary()) {
                continue;
            }
            for (EgressEvent event : egress) {
                if (event.pid() == null || instant(event.ts()).isBefore(instant(file.ts()))) {
                    continue;
                }
                List<Integer> processPath = processPath(file.pid(), event.pid(), parentByPid);
                if (!processPath.isEmpty()) {
                    chains.add(new EvidenceChain(
                            runId,
                            file.pid(),
                            file.path(),
                            event.pid(),
                            processPath,
                            event,
                            event.canaryMatch()));
                }
            }
        }
        return List.copyOf(chains);
    }

    private static Map<Integer, Integer> parentByPid(List<ProcEvent> proc) {
        Map<Integer, Integer> parentByPid = new HashMap<>();
        for (ProcEvent event : proc) {
            if ("execve".equals(event.event())) {
                parentByPid.put(event.pid(), event.ppid());
            }
        }
        return parentByPid;
    }

    private static List<Integer> processPath(int sourcePid, int targetPid, Map<Integer, Integer> parentByPid) {
        if (sourcePid == targetPid) {
            return List.of(sourcePid);
        }
        List<Integer> reversed = new ArrayList<>();
        Integer cursor = targetPid;
        Set<Integer> seen = new HashSet<>();
        while (cursor != null && seen.add(cursor)) {
            reversed.add(cursor);
            if (cursor == sourcePid) {
                ArrayList<Integer> path = new ArrayList<>();
                for (int i = reversed.size() - 1; i >= 0; i--) {
                    path.add(reversed.get(i));
                }
                return List.copyOf(path);
            }
            cursor = parentByPid.get(cursor);
        }
        return List.of();
    }

    private static Set<String> runIds(RunEvents events) {
        Set<String> runIds = new LinkedHashSet<>();
        events.network().forEach(event -> runIds.add(event.runId()));
        events.dns().forEach(event -> runIds.add(event.runId()));
        events.http().forEach(event -> runIds.add(event.runId()));
        events.files().forEach(event -> runIds.add(event.runId()));
        events.proc().forEach(event -> runIds.add(event.runId()));
        runIds.removeIf(Objects::isNull);
        return runIds;
    }

    private static boolean sameDestination(NetworkEvent left, NetworkEvent right) {
        return left.dstPort() == right.dstPort() && Objects.equals(left.dstIp(), right.dstIp());
    }

    private static boolean protoCompatible(String left, String right) {
        if (Objects.equals(left, right)) {
            return true;
        }
        return "other".equals(left) || "other".equals(right);
    }

    private static Instant instant(String ts) {
        try {
            return Instant.parse(ts);
        } catch (DateTimeParseException ex) {
            return Instant.EPOCH;
        }
    }
}
