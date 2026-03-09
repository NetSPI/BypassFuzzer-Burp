package com.bypassfuzzer.burp.core.collaborator;

import burp.api.montoya.MontoyaApi;

/**
 * Shared Burp Collaborator availability and payload helpers.
 */
public final class CollaboratorSupport {

    private CollaboratorSupport() {
    }

    public static boolean isAvailable(MontoyaApi api) {
        if (api == null) {
            return false;
        }

        try {
            return api.collaborator() != null && api.collaborator().defaultPayloadGenerator() != null;
        } catch (Exception e) {
            return false;
        }
    }

    public static String generatePayload(MontoyaApi api) {
        if (!isAvailable(api)) {
            return null;
        }

        try {
            return api.collaborator().defaultPayloadGenerator().generatePayload().toString();
        } catch (Exception e) {
            return null;
        }
    }
}
