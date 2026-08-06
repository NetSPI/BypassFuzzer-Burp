package com.bypassfuzzer.burp.core.coverage;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenApiSpecParserTest {

    @Test
    void parsesYamlOperationsParametersAndJsonRequestBody() {
        String spec = """
            openapi: 3.0.3
            servers:
              - url: https://api.example.test/v1
            paths:
              /users/{id}:
                parameters:
                  - name: id
                    in: path
                    required: true
                    schema:
                      type: integer
                      example: 42
                get:
                  parameters:
                    - name: verbose
                      in: query
                      schema:
                        type: boolean
                        default: true
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          type: object
                          properties:
                            role:
                              type: string
                              example: admin
            """;

        List<OpenApiOperation> operations = new OpenApiSpecParser().parse(spec, "openapi.yaml");

        assertEquals(2, operations.size());
        OpenApiOperation get = operations.stream().filter(operation -> operation.method().equals("GET")).findFirst().orElseThrow();
        OpenApiOperation post = operations.stream().filter(operation -> operation.method().equals("POST")).findFirst().orElseThrow();
        assertEquals("https://api.example.test/v1/users/42?verbose=true", get.url());
        assertEquals("application/json", post.headers().get("Content-Type"));
        assertEquals("{\"role\":\"admin\"}", post.body());
    }

    @Test
    void replacesEmptyFormExampleWithGeneratedSchemaBody() {
        String spec = """
            openapi: 3.0.0
            servers: [{url: https://api.example.test}]
            paths:
              /oauth2/token:
                post:
                  requestBody:
                    content:
                      application/x-www-form-urlencoded:
                        example: {}
                        schema:
                          type: object
                          properties:
                            grant_type: {type: string, enum: [client_credentials]}
                            client_id: {type: string, example: your-client-id}
                            client_secret: {type: string, example: your-client-secret}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("application/x-www-form-urlencoded", operation.headers().get("Content-Type"));
        assertEquals("grant_type=client_credentials&client_id=your-client-id&client_secret=your-client-secret",
            operation.body());
    }

    @Test
    void supportsNamedExamplesAndMissingServers() {
        String spec = """
            openapi: 3.0.0
            paths:
              /profiles:
                post:
                  requestBody:
                    content:
                      application/json:
                        examples:
                          primary:
                            value: {email: named@example.com}
                        schema:
                          allOf:
                            - type: object
                              properties:
                                id: {type: string, format: uuid}
                            - type: object
                              properties:
                                enabled: {type: boolean}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("https://localhost/profiles", operation.url());
        assertEquals("{\"email\":\"named@example.com\"}", operation.body());
    }

    @Test
    void generatesBodiesFromComposedSchemasAndFormats() {
        String spec = """
            openapi: 3.0.0
            servers: [{url: https://api.example.test}]
            paths:
              /profiles:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          allOf:
                            - type: object
                              properties:
                                id: {type: string, format: uuid}
                            - type: object
                              properties:
                                enabled: {type: boolean}
            """;

        OpenApiOperation operation = new OpenApiSpecParser().parse(spec, "openapi.yaml").get(0);

        assertEquals("{\"id\":\"00000000-0000-4000-8000-000000000000\",\"enabled\":true}",
            operation.body());
    }

    @Test
    void parsesSwaggerTwoAndAllowsBaseUrlOverride() {
        String spec = """
            {
              "swagger": "2.0",
              "host": "documented.example",
              "basePath": "/api",
              "schemes": ["https"],
              "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}}
            }
            """;

        List<OpenApiOperation> documented = new OpenApiSpecParser().parse(spec, "swagger.json");
        List<OpenApiOperation> overridden = new OpenApiSpecParser().parse(spec, "swagger.json", "http://localhost:8080/base");

        assertEquals("https://documented.example/api/health", documented.get(0).url());
        assertEquals("http://localhost:8080/base/health", overridden.get(0).url());
        assertTrue(overridden.get(0).headers().isEmpty());
    }
}
