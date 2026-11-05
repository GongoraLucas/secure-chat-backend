import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Response } from 'express';

/**
 * Formato único de error de AUTH (§11): `{statusCode, message}`.
 * Nunca stack traces ni detalles internos; los errores no HTTP salen como 500 genérico.
 */
@Catch()
export class HttpErrorFilter implements ExceptionFilter {
  private readonly logger = new Logger('Errors');

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();

    if (exception instanceof HttpException) {
      const statusCode = exception.getStatus();
      const body = exception.getResponse();
      let message: string = exception.message;
      if (typeof body === 'string') message = body;
      else if (typeof body === 'object' && body !== null && 'message' in body) {
        const m = (body as { message: unknown }).message;
        message = Array.isArray(m) ? m.join('; ') : String(m);
      }
      res.status(statusCode).json({ statusCode, message });
      return;
    }

    // Errores del body-parser (JSON mal formado, cuerpo enorme) traen un status 4xx propio.
    const status = (exception as { status?: unknown })?.status;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      res
        .status(status)
        .json({ statusCode: status, message: 'Petición inválida' });
      return;
    }

    const name = exception instanceof Error ? exception.name : 'unknown';
    this.logger.error(`unhandled_error type=${name}`);
    res
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ statusCode: 500, message: 'Error interno' });
  }
}
