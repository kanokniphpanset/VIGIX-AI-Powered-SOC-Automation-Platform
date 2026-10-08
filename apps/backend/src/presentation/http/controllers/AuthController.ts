import { Request, Response } from "express";
import { LoginUseCase } from "../../../application/identity/use-cases/Login.usecase";
import { loginSchema } from "../../../application/identity/dto/LoginDto";
import { ChangePasswordUseCase } from "../../../application/identity/use-cases/ChangePassword.usecase";
import { changePasswordSchema } from "../../../application/identity/dto/ChangePasswordDto";
import { ChangeEmailUseCase } from "../../../application/identity/use-cases/ChangeEmail.usecase";
import { changeEmailSchema } from "../../../application/identity/dto/ChangeEmailDto";
import { authenticatedTenant } from "../middlewares/auth.middleware";
import { validateBody } from "../validators/validateBody";

export class AuthController {
  constructor(
    private readonly loginUseCase: LoginUseCase,
    private readonly changePasswordUseCase?: ChangePasswordUseCase,
    private readonly changeEmailUseCase?: ChangeEmailUseCase
  ) {}

  login = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(loginSchema, req, res);
    if (!body) return;

    const result = await this.loginUseCase.execute(body);
    if (result.isFailure) {
      res.status(401).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  /**
   * POST /change-password — the authenticated user's own password (identity from the JWT only; the strict body has no
   * identity fields). A wrong current password is 400, not 401: the client treats every 401 as an expired session.
   */
  changePassword = async (req: Request, res: Response): Promise<void> => {
    if (!this.changePasswordUseCase) {
      res.status(501).json({ error: "NOT_IMPLEMENTED" });
      return;
    }
    const body = validateBody(changePasswordSchema, req, res);
    if (!body) return;
    const result = await this.changePasswordUseCase.execute({ ...body, userId: req.user!.id, tenantId: authenticatedTenant(req) });
    if (result.isFailure) {
      const error = result.error;
      if (error.code === "USER_NOT_FOUND") res.status(404).json({ error: "NOT_FOUND" });
      else if (error.code === "PASSWORD_POLICY_VIOLATION") res.status(400).json({ error: error.code, rules: error.rules });
      else res.status(400).json({ error: error.code });
      return;
    }
    res.json(result.value);
  };

  /**
   * POST /change-email — the authenticated user's own sign-in email (identity from the JWT only; current password
   * required). Wrong password is 400 (not 401, which the client treats as an expired session); a taken email is 409.
   */
  changeEmail = async (req: Request, res: Response): Promise<void> => {
    if (!this.changeEmailUseCase) {
      res.status(501).json({ error: "NOT_IMPLEMENTED" });
      return;
    }
    const body = validateBody(changeEmailSchema, req, res);
    if (!body) return;
    const result = await this.changeEmailUseCase.execute({ ...body, userId: req.user!.id, tenantId: authenticatedTenant(req) });
    if (result.isFailure) {
      const { code } = result.error;
      res.status(code === "USER_NOT_FOUND" ? 404 : code === "EMAIL_TAKEN" ? 409 : 400).json({ error: code === "USER_NOT_FOUND" ? "NOT_FOUND" : code });
      return;
    }
    res.json(result.value);
  };
}
