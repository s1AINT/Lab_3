using System;

class Program
{
    static void Main()
    {
        string message = "vasilmk1";
        byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        Console.WriteLine("Message to encode: " + message);
        byte[] text = System.Text.Encoding.UTF8.GetBytes(message);

        DESEncryptor encryptor = new DESEncryptor();
        byte[] encrypted = encryptor.Perform(text, key);

        DESDecryptor decryptor = new DESDecryptor();
        byte[] decrypted = decryptor.Perform(encrypted, key);

        Console.WriteLine();
        Console.WriteLine("Decoded message: " + System.Text.Encoding.UTF8.GetString(decrypted));
    }
}

abstract class DES
{
    public abstract byte[] Perform(byte[] input, byte[] key);
}

class DESEncryptor : DES
{
    public override byte[] Perform(byte[] input, byte[] key)
    {
        DESUtils.Permutation(ref input, DESUtils.IP);

        byte[] left = input[..4];
        byte[] right = input[4..];

        for (int i = 0; i < 16; i++)
        {
            byte[] expanded = DESUtils.Expand(right);
            byte[] roundKey = DESUtils.GenerateRoundKey(key, i);
            byte[] result = DESUtils.XOR(expanded, roundKey);
            result = DESUtils.Substitute(result);
            result = DESUtils.Permute(result, DESUtils.P);
            result = DESUtils.XOR(left, result);

            left = right;
            right = result;
        }

        byte[] resultText = right.Concat(left).ToArray();
        DESUtils.Permutation(ref resultText, DESUtils.FP);

        return resultText;
    }
}

class DESDecryptor : DES
{
    public override byte[] Perform(byte[] input, byte[] key)
    {
        DESUtils.Permutation(ref input, DESUtils.IP);

        byte[] left = input[..4];
        byte[] right = input[4..];

        for (int i = 15; i >= 0; i--)
        {
            byte[] expanded = DESUtils.Expand(left);
            byte[] roundKey = DESUtils.GenerateRoundKey(key, i);
            byte[] result = DESUtils.XOR(expanded, roundKey);
            result = DESUtils.Substitute(result);
            result = DESUtils.Permute(result, DESUtils.P);
            result = DESUtils.XOR(right, result);

            right = left;
            left = result;
        }

        byte[] resultText = left.Concat(right).ToArray();
        DESUtils.Permutation(ref resultText, DESUtils.FP);

        return resultText;
    }
}

static class DESUtils
{
    public static readonly int[] IP = { 2, 6, 3, 1, 4, 8, 5, 7 };
    public static readonly int[] FP = { 4, 1, 3, 5, 7, 2, 8, 6 };
    public static readonly int[] E = { 4, 1, 2, 3, 2, 3, 4, 1 };
    public static readonly int[] P = { 2, 4, 3, 1, 4, 3, 2, 1 };

    public static void Permutation(ref byte[] data, int[] table)
    {
        byte[] temp = new byte[table.Length];
        for (int i = 0; i < table.Length; i++)
        {
            temp[i] = data[table[i] - 1];
        }
        temp.CopyTo(data, 0);
    }

    public static byte[] XOR(byte[] a, byte[] b)
    {
        int length = Math.Min(a.Length, b.Length);
        byte[] result = new byte[length];

        for (int i = 0; i < length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }

    public static byte[] Expand(byte[] data)
    {
        byte[] result = new byte[E.Length];
        for (int i = 0; i < E.Length; i++)
        {
            result[i] = data[E[i] - 1];
        }
        return result;
    }

    public static byte[] Substitute(byte[] data)
    {
        byte[] result = new byte[data.Length / 2];

        for (int i = 0; i < data.Length; i += 2)
        {
            int row = (data[i] & 0xF0) >> 4;
            int col = i / 2;

            result[col] = S_BOXES[col, row];
        }

        return result;
    }

    public static byte[] Permute(byte[] data, int[] table)
    {
        byte[] result = new byte[table.Length];
        for (int i = 0; i < table.Length; i++)
        {
            int index = table[i] - 1;
            if (index >= 0 && index < data.Length)
            {
                result[i] = data[index];
            }
            else
            {
                result[i] = 0;
            }
        }
        return result;
    }

    public static byte[] GenerateRoundKey(byte[] key, int round)
    {
        byte[] result = new byte[6];
        for (int i = 0; i < 6; i++)
        {
            result[i] = key[(round * 6 + i) % key.Length];
        }
        return result;
    }

    public static readonly byte[,] S_BOXES =
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };
}
