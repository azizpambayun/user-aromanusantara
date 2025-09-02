package com.harumnusantara.user.exception;

import lombok.experimental.StandardException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
@StandardException
public class UnauthorizedException extends RuntimeException {
}
