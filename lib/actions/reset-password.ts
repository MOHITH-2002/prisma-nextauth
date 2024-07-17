'use server';

import * as z from 'zod';
import { ResetSchema } from '../zodSchema';
import { generatePasswordResetToken } from '../token';
import { sendPasswordResetEmail } from '../Email/mail';
import { getUserByEmail } from '../data';



export const resetPassword = async (values: z.infer<typeof ResetSchema>) => {
  const validatedFields = ResetSchema.safeParse(values);

  if (!validatedFields.success) {
    return { error: "Invalid email!" };
  }

  const { email } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (!existingUser) {
       return { error: "Email not found!" };
  }

  const passwordResetToken = await generatePasswordResetToken(email);

  await sendPasswordResetEmail(passwordResetToken.email, passwordResetToken.token);

    return { success: "Reset email sent!" };
};