package com.thorfinn.poc;

import com.thorfinn.models.Finding;

import java.util.List;

public interface poc {
    List<Finding> generateFindings() throws Exception;
}
