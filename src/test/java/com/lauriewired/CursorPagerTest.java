package com.lauriewired;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

public class CursorPagerTest {

    @Test
    public void cursorPresenceOnlyWithMoreAndContiguousSlices() {
        List<String> dataset = IntStream.range(0, 5)
            .mapToObj(i -> "item-" + i)
            .collect(Collectors.toList());

        CursorPager.CursorRequest request = new CursorPager.CursorRequest(
            "route",
            "fixture",
            0,
            2,
            2,
            10,
            null
        );

        CursorPager.CursorPage first = CursorPager.fromList(dataset, request);
        assertTrue(first.hasMore());
        assertNotNull(first.cursor());
        assertEquals(List.of("item-0", "item-1"), first.items());

        CursorPager.CursorRequest secondRequest = new CursorPager.CursorRequest(
            "route",
            "fixture",
            0,
            2,
            2,
            10,
            first.cursor()
        );
        CursorPager.CursorPage second = CursorPager.fromList(dataset, secondRequest);
        assertTrue(second.hasMore());
        assertNotNull(second.cursor());
        assertEquals(List.of("item-2", "item-3"), second.items());
        assertEquals(first.nextOffset(), 2);
        assertEquals(second.nextOffset(), 4);

        CursorPager.CursorRequest thirdRequest = new CursorPager.CursorRequest(
            "route",
            "fixture",
            0,
            2,
            2,
            10,
            second.cursor()
        );
        CursorPager.CursorPage third = CursorPager.fromList(dataset, thirdRequest);
        assertFalse(third.hasMore());
        assertNull(third.cursor());
        assertEquals(List.of("item-4"), third.items());
        assertEquals(5, third.nextOffset());
    }

    @Test
    public void contractEdgeCases() {
        CursorPager.CursorRequest emptyRequest = new CursorPager.CursorRequest(
            "route",
            "empty",
            0,
            3,
            3,
            10,
            null
        );
        CursorPager.CursorPage emptyPage = CursorPager.fromList(List.of(), emptyRequest);
        assertFalse(emptyPage.hasMore());
        assertTrue(emptyPage.items().isEmpty());
        assertNull(emptyPage.cursor());

        List<String> boundaryDataset = List.of("a", "b", "c", "d");
        CursorPager.CursorRequest boundaryRequest = new CursorPager.CursorRequest(
            "route",
            "boundary",
            0,
            2,
            2,
            10,
            null
        );
        CursorPager.CursorPage boundaryFirst = CursorPager.fromList(boundaryDataset, boundaryRequest);
        assertTrue(boundaryFirst.hasMore());
        assertEquals(List.of("a", "b"), boundaryFirst.items());
        assertNotNull(boundaryFirst.cursor());

        CursorPager.CursorRequest boundarySecondRequest = new CursorPager.CursorRequest(
            "route",
            "boundary",
            0,
            2,
            2,
            10,
            boundaryFirst.cursor()
        );
        CursorPager.CursorPage boundarySecond = CursorPager.fromList(boundaryDataset, boundarySecondRequest);
        assertFalse(boundarySecond.hasMore());
        assertNull(boundarySecond.cursor());
        assertEquals(List.of("c", "d"), boundarySecond.items());

        List<String> lastPageDataset = List.of("alpha", "bravo", "charlie", "delta", "echo");
        CursorPager.CursorRequest lastPageRequest = new CursorPager.CursorRequest(
            "route",
            "last",
            3,
            5,
            5,
            10,
            null
        );
        CursorPager.CursorPage lastPage = CursorPager.fromList(lastPageDataset, lastPageRequest);
        assertFalse(lastPage.hasMore());
        assertEquals(List.of("delta", "echo"), lastPage.items());

        CursorPager.CursorPage deterministicRepeat = CursorPager.fromList(lastPageDataset, lastPageRequest);
        assertEquals(lastPage.items(), deterministicRepeat.items());
        assertEquals(lastPage.cursor(), deterministicRepeat.cursor());
    }

    @Test
    public void goldenTwoPageWalk() {
        List<String> fixture = new ArrayList<>();
        fixture.add("alpha");
        fixture.add("bravo");
        fixture.add("charlie");

        CursorPager.CursorRequest request = new CursorPager.CursorRequest(
            "golden",
            "fixture",
            0,
            2,
            2,
            10,
            null
        );

        CursorPager.CursorPage first = CursorPager.fromList(fixture, request);
        String jsonFirst = CursorPager.toJson(first, CursorPager::defaultEscaper);
        String expectedFirst = "{\"items\":[\"alpha\",\"bravo\"],\"has_more\":true,\"cursor\":\"" + first.cursor() + "\"}";
        assertEquals(expectedFirst, jsonFirst);

        CursorPager.CursorRequest secondRequest = new CursorPager.CursorRequest(
            "golden",
            "fixture",
            0,
            2,
            2,
            10,
            first.cursor()
        );
        CursorPager.CursorPage second = CursorPager.fromList(fixture, secondRequest);
        String jsonSecond = CursorPager.toJson(second, CursorPager::defaultEscaper);
        assertEquals("{\"items\":[\"charlie\"],\"has_more\":false}", jsonSecond);

        List<String> walked = new ArrayList<>();
        walked.addAll(first.items());
        walked.addAll(second.items());
        assertEquals(fixture, walked);
    }

    @Test
    public void marksTruncationWhenInspectionCapHit() {
        CursorPager.CursorRequest request = new CursorPager.CursorRequest(
            "capTest",
            "discriminator",
            0,
            2,
            2,
            10,
            null
        );

        CursorPager.ResolvedRequest resolved = CursorPager.resolve(request);
        CursorPager.CursorPage page = CursorPager.buildPage(resolved, List.of("hit-0"), false);
        String json = CursorPager.toJson(page, CursorPager::defaultEscaper,
            "inspection cap reached after 3 instructions");

        assertEquals("{\"items\":[\"hit-0\"],\"has_more\":false,\"truncated\":true,"
            + "\"reason\":\"inspection cap reached after 3 instructions\"}", json);
    }

    private static CursorPager.CursorRequest search(String discriminator, String cursor) {
        return new CursorPager.CursorRequest("searchFunctions", discriminator, 0, 2, 2, 10, cursor);
    }

    @Test
    public void aCursorFromThisSearchResumesWhereItLeftOff() {
        List<String> items = List.of("a", "b", "c", "d");
        CursorPager.CursorPage first = CursorPager.fromList(items, search("q", null));
        CursorPager.CursorPage second = CursorPager.fromList(items, search("q", first.cursor()));
        assertEquals(List.of("c", "d"), second.items());
    }

    @Test
    public void anUndecodableCursorIsRefusedNotRestarted() {
        for (String bad : List.of("garbage", "v2.x.y.2", "v1.!!.!!.2", "v1.c2VhcmNoRnVuY3Rpb25z.cQ.x")) {
            try {
                CursorPager.resolve(search("q", bad));
                fail("accepted cursor " + bad);
            } catch (CursorPager.InvalidCursorException expected) {
                // refused: page one again would read as the next page
            }
        }
    }

    @Test
    public void aCursorFromAnotherSearchIsRefused() {
        String fromQ = CursorPager.fromList(List.of("a", "b", "c"), search("q", null)).cursor();
        try {
            CursorPager.resolve(search("other", fromQ));
            fail("accepted a cursor issued for another query");
        } catch (CursorPager.InvalidCursorException expected) {
            assertTrue(expected.getMessage().contains("another search"));
        }
        try {
            CursorPager.resolve(new CursorPager.CursorRequest("searchScalars", "q", 0, 2, 2, 10, fromQ));
            fail("accepted a cursor issued for another route");
        } catch (CursorPager.InvalidCursorException expected) {
            // refused
        }
    }

    @Test
    public void anEmptyCursorMeansNoCursor() {
        assertEquals(0, CursorPager.resolve(search("q", "")).startOffset());
    }
}
