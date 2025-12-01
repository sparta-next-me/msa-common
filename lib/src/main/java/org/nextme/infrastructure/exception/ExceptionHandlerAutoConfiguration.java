package org.nextme.infrastructure.exception;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan("org.nextme.infrastructure.exception.handler")
public class ExceptionHandlerAutoConfiguration {
}