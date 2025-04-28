package com.giftedlabs.eventoria.config.application;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Value("{openapi.dev-url}")
    private String devUrl;

    @Value("{openapi.prod-url}")
    private String prodUrl;

    @Bean
    public OpenAPI myOpenAPI(){
        Server devServer = new Server();
        devServer.setUrl(devUrl);
        devServer.setDescription("Server URL for development environment");

        Server prodServer = new Server();
        prodServer.setUrl(prodUrl);
        prodServer.setDescription("Server URL for production environment");

        Contact contact = new Contact();
        contact.setName("Gifted Labs");
        contact.setEmail("juliusadjeteysowah@gmail.com");
        contact.setUrl("https://www.giftedlabs.com");

        License mitLicense = new License();
        mitLicense.setName("MIT License");
        mitLicense.setUrl("https://opensource.org/licenses/MIT");

        Info info = new Info()
                .title("Eventoria API")
                .version("1.0.0")
                .description("API documentation for Eventoria, a platform for managing events.")
                .termsOfService("https://www.giftedlabs.com/terms")
                .contact(contact)
                .license(mitLicense);

        // JWT Security Config
        final String securitySchemeName = "BearerAuth";

        return new OpenAPI()
                .addServersItem(devServer)
                .addServersItem(prodServer)
                .info(info)
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes(securitySchemeName,
                                new io.swagger.v3.oas.models.security.SecurityScheme()
                                        .type(io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT Authorization header using the Bearer scheme")));
    }

}
