import bcrypt from "bcryptjs";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import httpStatus from "http-status"
import {
  AuthProvider,
  Role,
  UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import ejs from "ejs";
import type {
  IForgotPasswordPayload,
  IGoogleLoginPayload,
  ILoginUserPayload,
  IRegisterPatientPayload,
  IRequestUser,
  IResetPasswordPayload,
  IVerifyEmailPayload,
} from "./auth.interface";
import { type TokenPayload } from "google-auth-library";
import { googleClient } from "../../lib/googleAuth";
import { redisClient } from "../../lib/redis";
import { transporter } from "../../lib/nodemailer";
import { AppError } from "../../utils/AppError";

const registerPatient = async (payload: IRegisterPatientPayload) => {
  const { name, password, patient: patientData } = payload;
  const email = payload.email.trim().toLowerCase();

  const isUserExists = await prisma.user.findUnique({
    where: { email },
  });

  if (isUserExists) {
    throw new Error("User with this email already exists");
  }

  const hashedPassword = await bcrypt.hash(
    password,
    Number(config.bcrypt_salt_rounds),
  );

  const expirationSeconds = 5 * 60;
  const otpKey = `patient-registration-otp:${email}`;
  const otpValue = crypto.randomInt(100000, 1000000).toString();

  await redisClient.set(otpKey, otpValue, {
    expiration: {
      type: "EX",
      value: expirationSeconds,
    },
  });

  const patientRegistrationKey = `patient-registration-data:${email}`;
  const redisUserDataPayload = {
    name,
    email,
    password: hashedPassword,
    patient: patientData,
  };

  await redisClient.set(
    patientRegistrationKey,
    JSON.stringify(redisUserDataPayload),
    {
      expiration: {
        type: "EX",
        value: expirationSeconds,
      },
    },
  );

  const templatePath = path.join(
    process.cwd(),
    "src/app/templates/registration-user-otp.ejs",
  );
  const templateData = {
    name,
    email,
    otp: otpValue,
    expirationMinutes: expirationSeconds / 60,
  };
  const html = await ejs.renderFile(templatePath, templateData);

  await transporter.sendMail({
    from: config.email_sender,
    to: email,
    subject: "Email Verification",
    // text:`Your OTP is ${otp}`
    // html:`<h1>Your OTP is ${otp}</h1>`
    html,
  });
};

const verifyPatientEmail = async (payload: IVerifyEmailPayload) => {
  const otp = payload.otp;
  const email = payload.email.trim().toLowerCase();

  const isUserExists = await prisma.user.findUnique({
    where: { email },
  });

  if (isUserExists?.status === "BLOCKED") {
    throw new AppError(httpStatus.BAD_REQUEST, "User Is Blocked.");
  }
  if (isUserExists?.emailVerified) {
    throw new AppError(httpStatus.BAD_REQUEST, "Email Already Verified.");
  }
  if (isUserExists?.isDeleted || isUserExists?.status === "DELETED") {
    throw new AppError(httpStatus.BAD_REQUEST, "User Is Deleted.");
  }

  const otpKey = `patient-registration-otp:${email}`;
  const redisOtp = await redisClient.get(otpKey);

  if (!redisOtp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }
  if (redisOtp !== otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "OTP does not match.");
  }

  await redisClient.del(otpKey);

  const patientRegistrationKey = `patient-registration-data:${email}`;
  const redisPatientData = await redisClient.get(patientRegistrationKey);
  if (!redisPatientData) {
    throw new AppError(httpStatus.BAD_REQUEST, "Patient Doesn't Exist");
  }
  const patientPayload: IRegisterPatientPayload = JSON.parse(redisPatientData);
  const createdUser = await prisma.user.create({
    data: {
      name: patientPayload.name,
      email: patientPayload.email,
      password: patientPayload.password,
      role: Role.PATIENT,
      status: UserStatus.ACTIVE,
      emailVerified: true,
      patient: {
        create: {
          name: patientPayload.name,
          email: patientPayload.email,
          contactNumber: patientPayload?.patient?.contactNumber || "",
        },
      },
    },
    omit: { password: true },
    include: { patient: true },
  });

  await redisClient.del(patientRegistrationKey);

  //Senting Welcoming Email to new user.
  const templatePath = path.join(
    process.cwd(),
    "src/app/templates/patient-welcome-email.ejs",
  );
  const templateData = {
    name: createdUser.name,
  };
  const html = await ejs.renderFile(templatePath, templateData);

  await transporter.sendMail({
    from: config.email_sender,
    to: email,
    subject: "Welcome To PH Healthcare System",
    // text:`Your OTP is ${otp}`
    // html:`<h1>Your OTP is ${otp}</h1>`
    html,
  });

  const { patient, ...user } = createdUser;
  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    user,
    patient,
    accessToken,
    refreshToken,
  };
};

const loginUser = async (payload: ILoginUserPayload) => {
  const { password } = payload;
  const email = payload.email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    // throw new Error("User not found");
    throw new AppError(httpStatus.NOT_FOUND,"User not found");
  }

  if (user.status === UserStatus.BLOCKED) {
    throw new AppError(httpStatus.UNAUTHORIZED, "User is blocked");
  }

  if (user.isDeleted || user.status === UserStatus.DELETED) {
    throw new AppError(httpStatus.UNAUTHORIZED, "User is deleted");
  }

  if (user.password === null && user.googleId != null) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User Already Has Account Registered With Gooogle.Try To Login With Google.",
    );
  }

  const isPasswordMatched = await bcrypt.compare(
    password,
    user.password as string,
  );

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid credentials");
  }

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    accessToken,
    refreshToken,
  };
};

const getMe = async (user: IRequestUser) => {
  const isUserExists = await prisma.user.findUnique({
    where: {
      id: user.userId,
    },
    include: {
      patient: true,
    },
    omit: {
      password: true,
    },
  });

  if (!isUserExists) {
    throw new AppError(httpStatus.UNAUTHORIZED, "User not found");
  }

  return isUserExists;
};

const refreshToken = async (token: string) => {
  const verifiedRefreshToken = jwtUtils.verifyToken(
    token,
    config.jwt_refresh_secret,
  );

  if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      (config.node_env === "development"
        ? verifiedRefreshToken.error
        : "Invalid refresh token") as string,
    );
  }

  const data = verifiedRefreshToken.data as JwtPayload;

  const user = await prisma.user.findUnique({
    where: { id: data.userId },
  });

  if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User is inactive or not found",
    );
  }

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    accessToken,
    refreshToken,
  };
};

const googleLogin = async (payload: IGoogleLoginPayload) => {
  let googleIdTokenPayload: TokenPayload | null | undefined = null;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: payload.idToken,
      audience: config.goole_client_id,
    });
    googleIdTokenPayload = ticket.getPayload();
  } catch (error) {
    console.log("Google Id Token Verification Failed", error);
    throw new AppError(
      error instanceof Error && "config" in error
        ? httpStatus.SERVICE_UNAVAILABLE
        : httpStatus.UNAUTHORIZED,
      "Invalid or Expired Google Id Token",
    );
  }

  if (!googleIdTokenPayload) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Invalid or Expired Google Id Token",
    );
  }

  if (!googleIdTokenPayload.email) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Google Email Not Found");
  }

  if (!googleIdTokenPayload.name) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "Google Email User Name Not Found",
    );
  }

  const ifPatientExistWithGoogleAuth = await prisma.user.findUnique({
    where: {
      email: googleIdTokenPayload.email,
      role: Role.PATIENT,
      googleId: googleIdTokenPayload.sub,
    },
  });

  let user = ifPatientExistWithGoogleAuth;
  if (!ifPatientExistWithGoogleAuth) {
    const ifPatientExistWithCredentials = await prisma.user.findUnique({
      where: {
        email: googleIdTokenPayload.email,
        role: Role.PATIENT,
        authProvider: AuthProvider.CREDENTIAL,
      },
    });

    if (ifPatientExistWithCredentials) {
      if (!ifPatientExistWithCredentials.emailVerified) {
        throw new AppError(httpStatus.FORBIDDEN, "Email Not Verified");
      }

      if (ifPatientExistWithCredentials.status === UserStatus.BLOCKED) {
        throw new AppError(httpStatus.FORBIDDEN, "User is Blocked");
      }

      if (
        ifPatientExistWithCredentials.isDeleted ||
        ifPatientExistWithCredentials.status === UserStatus.DELETED
      ) {
        throw new AppError(httpStatus.FORBIDDEN, "User is Deleted");
      }

      user = await prisma.user.update({
        where: {
          id: ifPatientExistWithCredentials.id,
        },
        data: {
          googleId: googleIdTokenPayload.sub,
        },
      });
    } else {
      //google register
      user = await prisma.user.create({
        data: {
          name: googleIdTokenPayload.name,
          email: googleIdTokenPayload.email,
          role: Role.PATIENT,
          googleId: googleIdTokenPayload.sub,
          authProvider: AuthProvider.GOOGLE,
          emailVerified: true,
          patient: {
            create: {
              name: googleIdTokenPayload.name,
              email: googleIdTokenPayload.email,
            },
          },
        },
      });
      //Senting Welcoming Email to new user.
      const templatePath = path.join(
        process.cwd(),
        "src/app/templates/patient-welcome-email.ejs",
      );
      const templateData = {
        name: user.name,
      };
      const html = await ejs.renderFile(templatePath, templateData);

      await transporter.sendMail({
        from: config.email_sender,
        to: user.email,
        subject: "Welcome To PH Healthcare System",
        // text:`Your OTP is ${otp}`
        // html:`<h1>Your OTP is ${otp}</h1>`
        html,
      });
    }
  }

  if (!user) {
    throw new Error("User Not Found");
  }

  if (user.status === UserStatus.BLOCKED) {
    throw new AppError(httpStatus.FORBIDDEN, "User is Blocked");
  }

  if (user.isDeleted || user.status === UserStatus.DELETED) {
    throw new AppError(httpStatus.FORBIDDEN, "User is Deleted");
  }

  const jwtPayload = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_access_secret,
    config.jwt_access_expires_in as SignOptions,
  );

  const refreshToken = jwtUtils.createToken(
    jwtPayload,
    config.jwt_refresh_secret,
    config.jwt_refresh_expires_in as SignOptions,
  );

  return {
    accessToken,
    refreshToken,
  };
};

const forgotPassword = async (payload: IForgotPasswordPayload) => {
  const { email } = payload;
  const isUserExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!isUserExists) {
    throw new Error("User Does Not Exist.");
  }
  if (isUserExists.status === "BLOCKED") {
    throw new Error("User Is Blocked.");
  }
  if (!isUserExists.emailVerified) {
    throw new Error("User not verified.");
  }
  if (isUserExists.isDeleted || isUserExists.status === "DELETED") {
    throw new Error("User Is Deleted.");
  }
  if (isUserExists.authProvider === "GOOGLE" && isUserExists.googleId) {
    throw new Error("User Has Acccount With Google.");
  }

  const otp = crypto.randomInt(100000, 1000000).toString();
  const key = `forgot-password-otp:${isUserExists.email}`;
  const expirationSeconds = 5 * 60;

  await redisClient.set(key, otp, {
    expiration: {
      type: "EX",
      value: expirationSeconds,
    },
  });

  const templatePath = path.join(
    process.cwd(),
    "src/app/templates/forgot-password.ejs",
  );
  const templateData = {
    name: isUserExists.name,
    otp,
    expirationMinutes: expirationSeconds / 60,
  };
  const html = await ejs.renderFile(templatePath, templateData);

  await transporter.sendMail({
    from: config.email_sender,
    to: isUserExists.email,
    subject: "Forgot Password",
    // text:`Your OTP is ${otp}`
    // html:`<h1>Your OTP is ${otp}</h1>`
    html,
  });
};

const resetPassword = async (payload: IResetPasswordPayload) => {
  const { email, otp, newPassword } = payload;
  const isUserExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!isUserExists) {
    throw new AppError(httpStatus.BAD_REQUEST, "User Does Not Exist.");
  }
  if (isUserExists.status === "BLOCKED") {
    throw new AppError(httpStatus.BAD_REQUEST, "User Is Blocked.");
  }
  if (!isUserExists.emailVerified) {
    throw new AppError(httpStatus.BAD_REQUEST, "User not verified.");
  }
  if (isUserExists.isDeleted || isUserExists.status === "DELETED") {
    throw new AppError(httpStatus.BAD_REQUEST, "User Is Deleted.");
  }
  if (isUserExists.authProvider === "GOOGLE" && isUserExists.googleId) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "User Has Acccount With Google.",
    );
  }

  const key = `forgot-password-otp:${isUserExists.email}`;
  const redisOtp = await redisClient.get(key);

  if (!redisOtp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP");
  }
  if (redisOtp !== otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "OTP does not match.");
  }

  const hashedPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await prisma.user.update({
    where: {
      email: isUserExists.email,
    },
    data: {
      password: hashedPassword,
    },
  });

  await redisClient.del([key]);

  const templatePath = path.join(
    process.cwd(),
    "src/app/templates/reset-password-success.ejs",
  );
  const templateData = {
    name: isUserExists.name,
  };
  const html = await ejs.renderFile(templatePath, templateData);

  await transporter.sendMail({
    from: config.email_sender,
    to: isUserExists.email,
    subject: "Password Changed",
    // text:`Your OTP is ${otp}`
    // html:`<h1>Your Password is changed</h1>`
    html,
  });
};

export const AuthService = {
  registerPatient,
  verifyPatientEmail,
  loginUser,
  getMe,
  refreshToken,
  googleLogin,
  forgotPassword,
  resetPassword,
};
