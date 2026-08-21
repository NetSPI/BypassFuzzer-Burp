package com.bypassfuzzer.burp.ui.dashboard;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class ActivityRegistry {
    public record Entry(ManagedActivity activity, Runnable openAction) { }

    private final CopyOnWriteArrayList<Entry> entries = new CopyOnWriteArrayList<>();

    public void register(ManagedActivity activity, Runnable openAction) {
        if (activity == null) return;
        unregister(activity.activityId());
        entries.add(new Entry(activity, openAction == null ? () -> { } : openAction));
    }

    public void unregister(String activityId) {
        entries.removeIf(entry -> entry.activity().activityId().equals(activityId));
    }

    public List<Entry> entries() {
        return List.copyOf(entries);
    }
}
