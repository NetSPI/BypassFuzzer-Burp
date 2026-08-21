package com.bypassfuzzer.burp.ui.dashboard;

public record ActivitySnapshot(String id, String mode, String target, ActivityState state,
                               String progress, int sentCount) {
    public boolean active() {
        return state != null && state.active();
    }

    public boolean paused() {
        return state == ActivityState.PAUSED;
    }
}
