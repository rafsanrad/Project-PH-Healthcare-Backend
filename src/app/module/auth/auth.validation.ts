import z, { email } from "zod";

const PatientRegistrationZodSchema = z.object({
  name: z
    .string("Not a string !!")
    .min(3, "Name must be atleast 3 characters.")
    .max(20, "Name should not longer than 20 characters"),
  email: z.email(),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters long" })
    .max(20, { message: "Password cannot exceed 20 characters" })
    .refine((val) => /[A-Z]/.test(val), {
      message: "Password must contain at least one uppercase letter",
    })
    .refine((val) => /[a-z]/.test(val), {
      message: "Password must contain at least one lowercase letter",
    })
    .refine((val) => /[0-9]/.test(val), {
      message: "Password must contain at least one number",
    })
    .refine((val) => /[!@#$%^&*]/.test(val), {
      message:
        "Password must contain at least one special character (!@#$%^&*)",
    }),
  patient: z
    .object({
      contactNumber: z.string().optional(),
    })
    .optional(),
});

const loginZodSchema = z.object({
  email: z.email(),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters long" })
    .max(20, { message: "Password cannot exceed 20 characters" })
    .refine((val) => /[A-Z]/.test(val), {
      message: "Password must contain at least one uppercase letter",
    })
    .refine((val) => /[a-z]/.test(val), {
      message: "Password must contain at least one lowercase letter",
    })
    .refine((val) => /[0-9]/.test(val), {
      message: "Password must contain at least one number",
    })
    .refine((val) => /[!@#$%^&*]/.test(val), {
      message:
        "Password must contain at least one special character (!@#$%^&*)",
    }),
});

export const UserValidation = {
  PatientRegistrationZodSchema,
  loginZodSchema
};
