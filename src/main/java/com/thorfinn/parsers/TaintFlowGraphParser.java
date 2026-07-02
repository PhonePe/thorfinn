package com.thorfinn.parsers;

import lombok.extern.slf4j.Slf4j;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class TaintFlowGraphParser {

    private static final Pattern NODE_PATTERN = Pattern.compile(
            "\"(VarNode\\{<([^>]+)>/([^}]+)\\})\"\\s*\\[(.+?)\\];");

    private static final Pattern EDGE_PATTERN = Pattern.compile(
            "\"(VarNode\\{[^\"]+\\})\"\\s*->\\s*\"(VarNode\\{[^\"]+\\})\"");

    public record TfgNode(
            String fullId,
            String classMethod,
            String className,
            String variable
    ) {}

    public record TfgFlowData(
            String sourceClass,
            String sinkClass,
            List<String> orderedPath,
            List<String> intermediateClasses,
            List<String> allInvolvedClasses,
            String flowDescription
    ) {}

    public static class ParsedGraph {
        final Map<String, TfgNode> nodes;
        final Map<String, List<String>> adjacency;
        final Map<String, List<String>> nodesByClass;

        ParsedGraph(Map<String, TfgNode> nodes, Map<String, List<String>> adjacency) {
            this.nodes = nodes;
            this.adjacency = adjacency;
            this.nodesByClass = new LinkedHashMap<>();
            for (TfgNode node : nodes.values()) {
                nodesByClass.computeIfAbsent(node.className, k -> new ArrayList<>()).add(node.fullId);
            }
        }
    }

    public ParsedGraph parseGraph(String dotFilePath) throws Exception {
        Path path = Path.of(dotFilePath);
        if (!Files.exists(path)) {
            log.warn("[!] TFG: .dot file not found: {}", dotFilePath);
            return null;
        }

        String content = Files.readString(path);
        Map<String, TfgNode> nodes = parseNodes(content);
        List<Edge> edges = parseEdges(content);

        Map<String, List<String>> adjacency = new LinkedHashMap<>();
        for (Edge edge : edges) {
            adjacency.computeIfAbsent(edge.from, k -> new ArrayList<>()).add(edge.to);
        }

        log.info("[*] TFG: Parsed {} nodes, {} edges, {} unique classes",
                nodes.size(), edges.size(),
                nodes.values().stream().map(TfgNode::className).distinct().count());

        return new ParsedGraph(nodes, adjacency);
    }

    public TfgFlowData findFlowPath(ParsedGraph graph, String sourceClass, String sinkClass) {
        if (graph == null) {
            return null;
        }

        List<String> sourceNodeIds = graph.nodesByClass.getOrDefault(sourceClass, Collections.emptyList());
        List<String> sinkNodeIds = graph.nodesByClass.getOrDefault(sinkClass, Collections.emptyList());

        if (sourceNodeIds.isEmpty()) {
            log.debug("[*] TFG: No nodes found for source class: {}", sourceClass);
            return null;
        }
        if (sinkNodeIds.isEmpty()) {
            log.debug("[*] TFG: No nodes found for sink class: {}", sinkClass);
            return null;
        }

        Set<String> sinkNodeSet = new HashSet<>(sinkNodeIds);

        List<String> bestPath = null;

        for (String startNodeId : sourceNodeIds) {
            List<String> path = bfsToAny(startNodeId, sinkNodeSet, graph.adjacency);
            if (path != null) {
                if (bestPath == null || path.size() < bestPath.size()) {
                    bestPath = path;
                }
            }
        }

        if (bestPath == null) {
            log.debug("[*] TFG: No path found from {} to {}", sourceClass, sinkClass);
            return null;
        }

        return buildFlowData(bestPath, graph.nodes, sourceClass, sinkClass);
    }

    private Map<String, TfgNode> parseNodes(String dotContent) {
        Map<String, TfgNode> nodes = new LinkedHashMap<>();
        Matcher matcher = NODE_PATTERN.matcher(dotContent);

        while (matcher.find()) {
            String fullId = matcher.group(1);
            String classMethod = matcher.group(2);
            String variable = matcher.group(3);

            String className = extractClassName(classMethod);

            TfgNode node = new TfgNode(fullId, classMethod, className, variable);
            nodes.put(fullId, node);
        }

        return nodes;
    }

    private record Edge(String from, String to) {}

    private List<Edge> parseEdges(String dotContent) {
        List<Edge> edges = new ArrayList<>();
        Matcher matcher = EDGE_PATTERN.matcher(dotContent);

        while (matcher.find()) {
            edges.add(new Edge(matcher.group(1), matcher.group(2)));
        }

        return edges;
    }

    private List<String> bfsToAny(String startId, Set<String> targetIds,
                                   Map<String, List<String>> adjacency) {
        if (targetIds.contains(startId)) {
            return new ArrayList<>(List.of(startId));
        }

        Deque<List<String>> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(new ArrayList<>(List.of(startId)));
        visited.add(startId);

        while (!queue.isEmpty()) {
            List<String> currentPath = queue.poll();
            String lastNode = currentPath.get(currentPath.size() - 1);

            for (String neighbor : adjacency.getOrDefault(lastNode, Collections.emptyList())) {
                if (visited.contains(neighbor)) {
                    continue;
                }
                visited.add(neighbor);

                List<String> newPath = new ArrayList<>(currentPath);
                newPath.add(neighbor);

                if (targetIds.contains(neighbor)) {
                    return newPath;
                }

                queue.add(newPath);
            }
        }

        return null;
    }

    private TfgFlowData buildFlowData(List<String> path, Map<String, TfgNode> nodes,
                                       String sourceClass, String sinkClass) {
        Set<String> seenClasses = new LinkedHashSet<>();
        List<String> allInvolvedClasses = new ArrayList<>();

        for (String nodeId : path) {
            TfgNode node = nodes.get(nodeId);
            if (node != null && !seenClasses.contains(node.className)) {
                seenClasses.add(node.className);
                allInvolvedClasses.add(node.className);
            }
        }

        List<String> intermediateClasses = new ArrayList<>();
        for (String cls : allInvolvedClasses) {
            if (!cls.equals(sourceClass) && !cls.equals(sinkClass)) {
                intermediateClasses.add(cls);
            }
        }

        StringBuilder desc = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            TfgNode node = nodes.get(path.get(i));
            if (node != null) {
                desc.append(node.className).append(".").append(node.variable);
            } else {
                desc.append(path.get(i));
            }
            if (i < path.size() - 1) {
                desc.append(" → ");
            }
        }

        return new TfgFlowData(
                sourceClass,
                sinkClass,
                path,
                intermediateClasses,
                allInvolvedClasses,
                desc.toString()
        );
    }

    private String extractClassName(String classMethod) {
        int colonIdx = classMethod.indexOf(':');
        if (colonIdx > 0) {
            return classMethod.substring(0, colonIdx).trim();
        }
        return classMethod.trim();
    }
}
