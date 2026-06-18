package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.responses.HttpResponse;

public final class CoverageSweepClassifier {

    private CoverageSweepClassifier() {
    }

    public static boolean isInteresting(CoverageSweepCandidate candidate, HttpResponse controlResponse, HttpResponse probeResponse) {
        if (candidate == null || probeResponse == null) {
            return false;
        }

        int probeStatus = probeResponse.statusCode();
        if (isClientError(probeStatus)) {
            return false;
        }

        int baselineStatus = controlResponse == null ? candidate.statusCode() : controlResponse.statusCode();
        if (isBlocked(baselineStatus) && (isSuccess(probeStatus) || isRedirect(probeStatus))) {
            return true;
        }
        if (isBlocked(baselineStatus) && !isBlocked(probeStatus)) {
            return true;
        }

        String baselineType = controlResponse == null ? candidate.contentType() : contentType(controlResponse);
        String probeType = contentType(probeResponse);
        if (!blank(baselineType) && !baselineType.equalsIgnoreCase(probeType)) {
            return true;
        }

        int baselineLength = controlResponse == null ? candidate.contentLength() : bodyLength(controlResponse);
        return Math.abs(bodyLength(probeResponse) - baselineLength) >= 100;
    }

    public static String signal(CoverageSweepCandidate candidate, HttpResponse controlResponse, HttpResponse probeResponse) {
        if (candidate == null || probeResponse == null) {
            return "";
        }

        int probeStatus = probeResponse.statusCode();
        if (isClientError(probeStatus)) {
            return "";
        }

        int baselineStatus = controlResponse == null ? candidate.statusCode() : controlResponse.statusCode();
        if (isBlocked(baselineStatus) && !isBlocked(probeStatus)) {
            return baselineStatus + " -> " + probeStatus;
        }

        String baselineType = controlResponse == null ? candidate.contentType() : contentType(controlResponse);
        String probeType = contentType(probeResponse);
        if (!blank(baselineType) && !baselineType.equalsIgnoreCase(probeType)) {
            return "Content-Type " + baselineType + " -> " + (blank(probeType) ? "-" : probeType);
        }

        int baselineLength = controlResponse == null ? candidate.contentLength() : bodyLength(controlResponse);
        int delta = bodyLength(probeResponse) - baselineLength;
        if (Math.abs(delta) >= 100) {
            return "Length " + (delta > 0 ? "+" : "") + delta;
        }

        return "";
    }

    private static boolean isBlocked(int status) {
        return status == 401 || status == 403;
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    private static boolean isRedirect(int status) {
        return status >= 300 && status < 400;
    }

    private static boolean isClientError(int status) {
        return status >= 400 && status < 500;
    }

    private static int bodyLength(HttpResponse response) {
        return response == null || response.body() == null ? 0 : response.body().length();
    }

    private static String contentType(HttpResponse response) {
        return response == null ? "" : response.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
            .map(header -> header.value())
            .findFirst()
            .orElse("");
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
