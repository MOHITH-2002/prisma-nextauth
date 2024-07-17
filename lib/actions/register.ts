"use server";
import bcrypt from "bcryptjs";
import * as z from "zod";
import { RegisterSchema } from "../zodSchema";

import { generateVerificationToken } from "../token";
import { sendVerificationEmail } from "../Email/mail";
import { db } from "../db";
import { getUserByEmail } from "../data";


export const register = async (values: z.infer<typeof RegisterSchema>) => {
  try {
    
  const validatedFields = RegisterSchema.safeParse(values);

  if (!validatedFields.success) {
    return { error: "Invalid fields!" };
  }
  const {email,name,password} = validatedFields.data;

  const existingUser = await getUserByEmail(email)
  if(existingUser) {
    return { error: "Email already exists!"}
  }
  const hashedPassword = await bcrypt.hash(password, 10);

  
  await db.user.create({
    data:
    { email,
      name,
      password:hashedPassword
    }});

  const verificationToken = await generateVerificationToken(email);

  await sendVerificationEmail(verificationToken.email, verificationToken.token);
  return { success: "Confirmation Email sent!" };
  } catch (error) {
    console.log(error);
    
  }
};