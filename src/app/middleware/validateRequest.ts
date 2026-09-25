import z from "zod";
import httpStatus from "http-status";
import { AppError } from "../utils/AppError";
import { catchAsync } from "../utils/catchAsync";
import { NextFunction, Request, Response } from "express";

export const validateRequest = (zodSchema: z.ZodObject) => {
  return catchAsync((req: Request, res: Response, next: NextFunction) => {
    // const payload=req.body? req.body : {}
    const payload = req.body ?? {};
    const result = zodSchema.safeParse(payload);
    if (!result.success) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        result.error.issues[0].message,
      );
    }
    req.body = result.data;
    next();
  });
};