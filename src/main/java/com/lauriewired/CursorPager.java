package com.lauriewired;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * Utility for cursor-based pagination. Encodes opaque resume tokens that capture the
 * logical route and discriminator (e.g. query) along with the next offset.
 */
public final class CursorPager {

    private static final String CURSOR_VERSION = "v1";

    private CursorPager() {
        // Utility class
    }

    /**
     * Request describing cursor pagination inputs.
     */
    public record CursorRequest(
        String routeKey,
        String discriminator,
        int offset,
        int limit,
        int defaultLimit,
        int maxLimit,
        String cursor
    ) {
        public CursorRequest {
            routeKey = Objects.requireNonNullElse(routeKey, "");
            discriminator = Objects.requireNonNullElse(discriminator, "");
        }
    }

    /**
     * Request with resolved start offset and sanitized limit.
     */
    public record ResolvedRequest(String routeKey, String discriminator, int startOffset, int limit) {
    }

    /**
     * Page of results and metadata.
     */
    public record CursorPage(List<String> items, boolean hasMore, String cursor, int nextOffset) {
        public CursorPage {
            items = List.copyOf(items);
        }
    }

    private record CursorState(String routeKey, String discriminator, int offset) {
    }

    /**
     * Resolve a {@link CursorRequest} into normalized offsets and bounds.
     */
    public static ResolvedRequest resolve(CursorRequest request) {
        int defaultLimit = request.defaultLimit() > 0 ? request.defaultLimit() : 1;
        int requestedLimit = request.limit() > 0 ? request.limit() : defaultLimit;
        if (request.maxLimit() > 0) {
            requestedLimit = Math.min(requestedLimit, request.maxLimit());
        }
        if (requestedLimit <= 0) {
            requestedLimit = defaultLimit;
        }

        int start = Math.max(0, request.offset());
        if (request.cursor() != null && !request.cursor().isEmpty()) {
            Optional<CursorState> state = decodeCursor(request.cursor());
            if (state.isPresent()) {
                CursorState cursorState = state.get();
                if (cursorState.routeKey().equals(request.routeKey())
                    && cursorState.discriminator().equals(request.discriminator())) {
                    start = Math.max(0, cursorState.offset());
                }
            }
        }

        return new ResolvedRequest(request.routeKey(), request.discriminator(), start, requestedLimit);
    }

    /**
     * Build a {@link CursorPage} from a fully materialized dataset.
     */
    public static CursorPage fromList(List<String> allItems, CursorRequest request) {
        ResolvedRequest resolved = resolve(request);
        if (allItems.isEmpty() || resolved.startOffset() >= allItems.size()) {
            return buildPage(resolved, Collections.emptyList(), false);
        }
        int end = Math.min(allItems.size(), resolved.startOffset() + resolved.limit());
        List<String> slice = new ArrayList<>(allItems.subList(resolved.startOffset(), end));
        boolean hasMore = end < allItems.size();
        return buildPage(resolved, slice, hasMore);
    }

    /**
     * Build a {@link CursorPage} from a subset of items with explicit hasMore flag.
     */
    public static CursorPage buildPage(ResolvedRequest resolved, List<String> pageItems, boolean hasMore) {
        String nextCursor = null;
        int nextOffset = resolved.startOffset();
        if (!pageItems.isEmpty()) {
            nextOffset += pageItems.size();
        }
        if (hasMore) {
            nextCursor = encodeCursor(resolved.routeKey(), resolved.discriminator(), nextOffset);
        }
        return new CursorPage(pageItems, hasMore, nextCursor, nextOffset);
    }

    /**
     * Serialize a page into JSON using the provided escaper.
     */
    public static String toJson(CursorPage page, Function<String, String> escaper) {
        Function<String, String> safeEscaper = escaper != null ? escaper : CursorPager::defaultEscaper;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"items\":[");
        List<String> items = page.items();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('\"').append(safeEscaper.apply(items.get(i))).append('\"');
        }
        sb.append("],\"has_more\":").append(page.hasMore());
        if (page.hasMore() && page.cursor() != null && !page.cursor().isEmpty()) {
            sb.append(",\"cursor\":\"").append(page.cursor()).append('\"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Build a JSON error payload with the pagination envelope.
     */
    public static String errorJson(String message, Function<String, String> escaper) {
        Function<String, String> safeEscaper = escaper != null ? escaper : CursorPager::defaultEscaper;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"items\":[],\"has_more\":false");
        if (message != null && !message.isEmpty()) {
            sb.append(",\"error\":\"").append(safeEscaper.apply(message)).append('\"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Default JSON escaper for cases where no custom escaper is provided.
     */
    public static String defaultEscaper(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                case '"':
                    escaped.append('\\').append(c);
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        escaped.append(c);
                    }
                    break;
            }
        }
        return escaped.toString();
    }

    private static String encodeCursor(String routeKey, String discriminator, int offset) {
        String routeSegment = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(routeKey.getBytes(StandardCharsets.UTF_8));
        String discSegment = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(discriminator.getBytes(StandardCharsets.UTF_8));
        return CURSOR_VERSION + '.' + routeSegment + '.' + discSegment + '.' + offset;
    }

    private static Optional<CursorState> decodeCursor(String cursor) {
        try {
            String[] parts = cursor.split("\\.", -1);
            if (parts.length != 4) {
                return Optional.empty();
            }
            if (!CURSOR_VERSION.equals(parts[0])) {
                return Optional.empty();
            }
            String route = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String disc = new String(Base64.getUrlDecoder().decode(parts[2]), StandardCharsets.UTF_8);
            int offset = Integer.parseInt(parts[3]);
            return Optional.of(new CursorState(route, disc, Math.max(0, offset)));
        }
        catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
