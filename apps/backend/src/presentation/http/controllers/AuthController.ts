import { Request, Response } from "express";
import { LoginUseCase } from "../../../application/identity/use-cases/Login.usecase";
import { loginSchema } from "../../../application/identity/dto/LoginDto";
import { validateBody } from "../validators/validateBody";

export class AuthController {
  constructor(private readonly loginUseCase: LoginUseCase) {}

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
}
