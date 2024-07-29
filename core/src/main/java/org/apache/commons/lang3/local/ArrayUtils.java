package org.apache.commons.lang3.local;

import java.lang.reflect.Array;

public class ArrayUtils {

    /**
     * An empty immutable {@link Class} array.
     */
    public static final Class<?>[] EMPTY_CLASS_ARRAY = {};

    /**
     * Defensive programming technique to change a {@code null}
     * reference to an empty one.
     * <p>
     * This method returns an empty array for a {@code null} input array.
     * </p>
     * <p>
     * As a memory optimizing technique an empty array passed in will be overridden with
     * the empty {@code public static} references in this class.
     * </p>
     *
     * @param array  the array to check for {@code null} or empty
     * @return the same array, {@code public static} empty array if {@code null} or empty input
     * @since 3.2
     */
    public static Class<?>[] nullToEmpty(final Class<?>[] array) {
        return nullTo(array, EMPTY_CLASS_ARRAY);
    }

    /**
     * Defensive programming technique to change a {@code null}
     * reference to an empty one.
     * <p>
     * This method returns a default array for a {@code null} input array.
     * </p>
     * <p>
     * As a memory optimizing technique an empty array passed in will be overridden with
     * the empty {@code public static} references in this class.
     * </p>
     *
     * @param <T> The array type.
     * @param array  the array to check for {@code null} or empty
     * @param defaultArray A default array, usually empty.
     * @return the same array, or defaultArray if {@code null} or empty input.
     * @since 3.15.0
     */
    public static  <T> T[] nullTo(final T[] array, final T[] defaultArray) {
        return isEmpty(array) ? defaultArray : array;
    }

    /**
     * Checks if an array of Objects is empty or {@code null}.
     *
     * @param array  the array to test
     * @return {@code true} if the array is empty or {@code null}
     * @since 2.1
     */
    public static boolean isEmpty(final Object[] array) {
        return isArrayEmpty(array);
    }

    /**
     * Checks if an array is empty or {@code null}.
     *
     * @param array the array to test
     * @return {@code true} if the array is empty or {@code null}
     */
    private static boolean isArrayEmpty(final Object array) {
        return getLength(array) == 0;
    }

    /**
     * Returns the length of the specified array.
     * This method can deal with {@link Object} arrays and with primitive arrays.
     * <p>
     * If the input array is {@code null}, {@code 0} is returned.
     * </p>
     * <pre>
     * ArrayUtils.getLength(null)            = 0
     * ArrayUtils.getLength([])              = 0
     * ArrayUtils.getLength([null])          = 1
     * ArrayUtils.getLength([true, false])   = 2
     * ArrayUtils.getLength([1, 2, 3])       = 3
     * ArrayUtils.getLength(["a", "b", "c"]) = 3
     * </pre>
     *
     * @param array  the array to retrieve the length from, may be null
     * @return The length of the array, or {@code 0} if the array is {@code null}
     * @throws IllegalArgumentException if the object argument is not an array.
     * @since 2.1
     */
    public static int getLength(final Object array) {
        return array != null ? Array.getLength(array) : 0;
    }

    /**
     * Checks whether two arrays are the same length, treating
     * {@code null} arrays as length {@code 0}.
     * <p>
     * Any multi-dimensional aspects of the arrays are ignored.
     * </p>
     *
     * @param array1 the first array, may be {@code null}
     * @param array2 the second array, may be {@code null}
     * @return {@code true} if length of arrays matches, treating
     *  {@code null} as an empty array
     * @since 3.11
     */
    public static boolean isSameLength(final Object array1, final Object array2) {
        return getLength(array1) == getLength(array2);
    }

    /**
     * Outputs an array as a String, treating {@code null} as an empty array.
     * <p>
     * Multi-dimensional arrays are handled correctly, including
     * multi-dimensional primitive arrays.
     * </p>
     * <p>
     * The format is that of Java source code, for example {@code {a,b}}.
     * </p>
     *
     * @param array  the array to get a toString for, may be {@code null}
     * @return a String representation of the array, '{}' if null array input
     */
    public static String toString(final Object array) {
        return toString(array, "{}");
    }

    /**
     * Outputs an array as a String handling {@code null}s.
     * <p>
     * Multi-dimensional arrays are handled correctly, including
     * multi-dimensional primitive arrays.
     * </p>
     * <p>
     * The format is that of Java source code, for example {@code {a,b}}.
     * </p>
     *
     * @param array  the array to get a toString for, may be {@code null}
     * @param stringIfNull  the String to return if the array is {@code null}
     * @return a String representation of the array
     */
    public static String toString(final Object array, final String stringIfNull) {
        if (array == null) {
            return stringIfNull;
        }
        // return new ToStringBuilder(array, ToStringStyle.SIMPLE_STYLE).append(array).toString();
        // TODO: add a proper implement
        return array.toString();
    }

}
