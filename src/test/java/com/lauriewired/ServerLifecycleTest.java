package com.lauriewired;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;

import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

public class ServerLifecycleTest {

    private static final class DummyContext implements ProgramCapable {
        private final boolean programContext;
        private final boolean programManagerService;

        DummyContext(boolean programContext, boolean programManagerService) {
            this.programContext = programContext;
            this.programManagerService = programManagerService;
        }

        @Override
        public boolean hasProgramContext() {
            return programContext;
        }

        @Override
        public boolean hasProgramManagerService() {
            return programManagerService;
        }
    }

    @Test
    public void promotesProgramCapableInstanceWhenAvailable() {
        GhidraMCPPlugin.PluginContextRegistry<DummyContext> registry =
            new GhidraMCPPlugin.PluginContextRegistry<>();
        DummyContext projectManager = new DummyContext(false, true);
        DummyContext codeBrowser = new DummyContext(true, false);

        registry.register(projectManager);
        assertTrue(registry.active(false).isPresent());
        assertFalse(registry.active(true).isPresent());

        registry.register(codeBrowser);
        assertTrue(registry.active(true).isPresent());
        assertEquals(codeBrowser, registry.active(true).get());

        registry.promote(projectManager);
        assertEquals(projectManager, registry.active(false).get());
        assertEquals("Should still return program-capable context when required", codeBrowser,
            registry.active(true).get());

        registry.unregister(projectManager);
        assertEquals(codeBrowser, registry.active(false).get());
    }

    @Test
    public void reusesHttpServerInstanceAcrossCalls() throws Exception {
        GhidraMCPPlugin.SharedHttpServerState state = new GhidraMCPPlugin.SharedHttpServerState();
        GhidraMCPPlugin.SharedHttpServerState.ServerHandle first = state.ensureServer(
            0, () -> HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0));
        GhidraMCPPlugin.SharedHttpServerState.ServerHandle second = state.ensureServer(
            9999, () -> {
                throw new IllegalStateException("Factory should not be invoked for existing server");
            });

        assertTrue(first.newlyCreated());
        assertFalse(second.newlyCreated());
        assertSame(first.server(), second.server());

        state.stopIfIdle(true);
    }
}
