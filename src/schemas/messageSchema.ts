import {z} from "zod";

export const messageSchema = z.object({
    content: z
        .string()
        .min(10, {message: "Content must be atleast 10 char long"})
        .max(300, {message: "Content must not exceed 300 characters"})
});
