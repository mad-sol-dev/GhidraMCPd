package com.lauriewired;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;

import org.junit.Test;

/** The captured output of /runScript: kept up to the limit, the rest only counted. */
public class ScriptOutputTest {

    @Test
    public void keepsOutputBelowTheLimit() {
        GhidraMCPPlugin.BoundedWriter out = new GhidraMCPPlugin.BoundedWriter(16);
        PrintWriter writer = new PrintWriter(out, true);
        writer.print("hello");
        writer.flush();
        assertEquals("hello", out.text());
        assertFalse(out.truncated());
    }

    @Test
    public void exactlyTheLimitIsNotTruncated() {
        GhidraMCPPlugin.BoundedWriter out = new GhidraMCPPlugin.BoundedWriter(5);
        PrintWriter writer = new PrintWriter(out, true);
        writer.print("hello");
        writer.flush();
        assertEquals("hello", out.text());
        assertFalse(out.truncated());
    }

    @Test
    public void cutsAtTheLimitAndSaysSo() {
        GhidraMCPPlugin.BoundedWriter out = new GhidraMCPPlugin.BoundedWriter(8);
        PrintWriter writer = new PrintWriter(out, true);
        writer.print("hello ");
        writer.print("world");
        writer.flush();
        assertEquals("hello wo", out.text());
        assertTrue(out.truncated());
    }
}
