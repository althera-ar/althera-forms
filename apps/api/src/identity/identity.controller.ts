/**
 * The identity module's HTTP surface (prefix /iam: the web's IAM_BASE_URL is
 * `<this API's public address>/iam`, so every contract route lives here).
 *
 * Public on purpose — the same why /health is public: the contract routes are
 * the login door. Credentials themselves only touch POST /iam/login, which is
 * throttled per IP with progressive per-email lockout. The bearer-protected
 * surface stays the /v1 + dashboard one it already was: the host auth provider
 * (WorkOsAuthProvider over the minted JWT) validates every one of its requests
 * exactly as it did when an upstream identity service minted tokens.
 */
import { Body, Controller, Get, Inject, NotFoundException, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import { IdentityService } from './identity.service';
import { IDENTITY } from '../tokens';

/**
 * The slice of the express Response these handlers need. Typed locally (the
 * repo holds no express type dependency): @Res() injects the platform's real
 * response object, and this only narrows what we touch.
 */
interface RenderableResponse {
  type(value: string): RenderableResponse;
  send(value: string): unknown;
  redirect(code: number, url: string): unknown;
}

interface IdentifiableRequest {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string };
}

type QueryBag = Record<string, string | string[] | undefined>;

function ip(req: IdentifiableRequest): string {
  const forwarded = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim();
  return forwarded || req.ip || req.socket?.remoteAddress || 'unknown';
}

@Controller('iam')
export class IdentityController {
  /**
   * The service is NULL on every other AUTH_PROVIDER (a `local`/`workos` boot
   * never validates identity env legs it will not use) — the routes then answer
   * 404, exactly how other conditional endpoints degrade (mcp-oauth).
   */
  constructor(@Inject(IDENTITY) private readonly identity: IdentityService | null) {}

  private get service(): IdentityService {
    if (!this.identity) throw new NotFoundException({ error: 'NOT_FOUND', message: 'Not found.' });
    return this.identity;
  }

  /** GET {IAM_BASE_URL}/auth/login-url → { loginUrl } — the web's first hop. */
  @Get('auth/login-url')
  loginUrl(@Query() query: QueryBag): { loginUrl: string } {
    return this.service.loginUrl(query);
  }

  /** GET {IDENTITY_PUBLIC_URL}/login → the hosted login page (form + error). */
  @Get('login')
  loginPage(@Query() query: QueryBag, @Res() res: RenderableResponse): void {
    const error = query.error === '1';
    res.type('html').send(this.service.loginPageHtml(query, error));
  }

  /**
   * POST the form: verify → mint → 302 straight to the web's callback with the
   * whole session in `?session=` (immediately consumed and 302'd to /admin, so
   * the blob never lands in the final URL's history). A failure is a redirect
   * BACK to the page — the only answer a plain HTML form can follow.
   */
  @Post('login')
  async loginSubmit(
    @Req() req: IdentifiableRequest,
    @Body() body: QueryBag,
    @Res() res: RenderableResponse,
  ): Promise<void> {
    const outcome = await this.service.loginSubmit(body, ip(req));
    if (typeof outcome === 'string') {
      res.redirect(302, outcome);
      return;
    }
    const handoff = this.service.validateReturnTo(body);
    res.redirect(302, this.service.errorBack(handoff, outcome.error));
  }

  /** POST {IAM_BASE_URL}/auth/refresh → rotate (or answer a grace racer). 401 otherwise. */
  @Post('auth/refresh')
  async refresh(
    @Body() body: { refresh_token?: string } | undefined,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const tokens = await this.service.refresh(body?.refresh_token);
    if (!tokens) throw new UnauthorizedException();
    return tokens;
  }

  /** POST {IAM_BASE_URL}/auth/logout?redirect=false → revoke. Always 200, per contract. */
  @Post('auth/logout')
  async logout(
    @Body() body: { workos_session_id?: string; session_id?: string } | undefined,
  ): Promise<{ logoutUrl: string | null }> {
    await this.service.logout(body?.workos_session_id ?? body?.session_id);
    return { logoutUrl: null };
  }
}
