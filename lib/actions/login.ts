"use server";

import * as z from "zod";
import bcrypt from "bcryptjs";
import { AuthError } from "next-auth";
import { DEFAULT_LOGIN_REDIRECT } from "@/routes";
import { LoginSchema } from "../zodSchema";
import { signIn } from "@/auth";
import { generateVerificationToken } from "../token";

import { sendVerificationEmail } from "../Email/mail";

import { getUserByEmail } from "../data";


export const login = async (values: z.infer<typeof LoginSchema>,callbackUrl?: string | null) => {

  const validatedFields = LoginSchema.safeParse(values);

  if (!validatedFields.success) {
    return { error: "Invalid fields!" };
  }


  const { email, password } = validatedFields.data;
  const existingUser = await getUserByEmail(email);

  if (!existingUser || !existingUser.email || !existingUser.password) {
    return { error: "Email does not exist!" };
  }

  if (!existingUser.emailVerified) {
    // console.log('Email not verified. Sending verification...');
    const verificationToken = await generateVerificationToken(existingUser.email);

    await sendVerificationEmail(verificationToken.email, verificationToken.token);

    return { success: 'Confirmation Email sent!' };

  }

    const passwordMatch = await bcrypt.compare(password, existingUser.password);

    if (!passwordMatch) {
    return { error: "Invalid Credentials!" };
    }

  try {
    await signIn("credentials", {
      email,
      password,
      redirectTo: callbackUrl || DEFAULT_LOGIN_REDIRECT,
    })
    console.log("success");
    
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case "CredentialsSignin":
          return { error: "Invalid credentials!" }
        default:
          return { error: "Something went wrong!" }
      }
    }

    throw error;
  }
};