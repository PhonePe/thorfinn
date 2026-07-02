package com.thorfinn.parsers;

public interface Parsers<T> {
    T parse() throws Exception;
}
