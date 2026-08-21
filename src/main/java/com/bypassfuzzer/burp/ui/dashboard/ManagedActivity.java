package com.bypassfuzzer.burp.ui.dashboard;

public interface ManagedActivity {
    String activityId();
    ActivitySnapshot activitySnapshot();
    void pauseActivity();
    void resumeActivity();
    void stopActivity();
}
