import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from "next-auth/providers/credentials";
import z from "zod";
import postgres from "postgres";
import { Invoice, User } from "@/app/lib/definitions";
import bcrypt from 'bcrypt';
import { getSql } from "@/app/lib/data";


async function getUser(email: string): Promise<User | undefined> {
	console.log('provided email', email)
	try {
		const user = await getSql()<User[]>`SELECT * FROM public.users WHERE email = ${email}`;
		// const users = await getSql()<User[]>`SELECT * FROM public.users`;
		// return users.find(u => u.email === email);
		return user.at(0)
	} catch (error) {
		console.error('Failed to fetch user:', error);
		throw new Error('Failed to fetch user.');
	}
}

export const { auth, signIn, signOut } = NextAuth({
	...authConfig,
	providers: [Credentials({
		authorize: async (credentials) => {
			const parsedCredentials = z
				.object({
					email: z.string().email(),
					password: z.string().min(6),
				})
				.safeParse(credentials);

			if (parsedCredentials.success) {
				const { email, password } = parsedCredentials.data;
				const user = await getUser(email);

				if (!user) return null;
				const passwordsMatch = await bcrypt.compare(password, user.password);

				if (passwordsMatch) return user;
			}

			console.warn('Invalid login attempt:', parsedCredentials);
			return null;
		}
	})],
});