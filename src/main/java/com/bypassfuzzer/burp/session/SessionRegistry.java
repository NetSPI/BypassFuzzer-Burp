package com.bypassfuzzer.burp.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;

import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks open fuzzing sessions and guarantees explicit disposal.
 */
public class SessionRegistry {

    private final MontoyaApi api;
    private final GlobalTrafficGovernor globalGovernor;
    private final Map<String, FuzzingSessionController> sessions = new ConcurrentHashMap<>();

    public SessionRegistry(MontoyaApi api) {
        this(api, new GlobalTrafficGovernor());
    }

    public SessionRegistry(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this.api = api;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
    }

    public FuzzingSessionController createSession(HttpRequest request) {
        FuzzingSessionController controller = new FuzzingSessionController(api, request, globalGovernor);
        sessions.put(controller.sessionId(), controller);
        return controller;
    }

    public void closeSession(String sessionId) {
        FuzzingSessionController controller = sessions.remove(sessionId);
        if (controller != null) {
            controller.dispose();
        }
    }

    public void closeAllSessions() {
        for (String sessionId : new ArrayList<>(sessions.keySet())) {
            closeSession(sessionId);
        }
    }
}
