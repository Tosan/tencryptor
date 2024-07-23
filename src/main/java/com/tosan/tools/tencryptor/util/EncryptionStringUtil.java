package com.tosan.tools.tencryptor.util;

/**
 * @author mazahernasab
 * @since 5/26/2024
 **/
public class EncryptionStringUtil {
    public static final char LF = '\n';
    public static final char CR = '\r';
    public static final String EMPTY = "";

    public static String chomp(final String str) {
        if (isEmpty(str)) {
            return str;
        }

        if (str.length() == 1) {
            final char ch = str.charAt(0);
            if (ch == CR || ch == LF) {
                return EMPTY;
            }
            return str;
        }

        int lastIdx = str.length() - 1;
        final char last = str.charAt(lastIdx);

        if (last == LF) {
            if (str.charAt(lastIdx - 1) == CR) {
                lastIdx--;
            }
        } else if (last != CR) {
            lastIdx++;
        }
        return str.substring(0, lastIdx);
    }

    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }
}
