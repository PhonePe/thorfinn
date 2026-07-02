package com.thorfinn.poc;

import com.phonepe.sentinelai.core.agent.AgentInput;
import com.phonepe.sentinelai.core.agent.AgentOutput;
import com.phonepe.sentinelai.core.errors.ErrorType;
import com.thorfinn.config.ToolsConfig;
import com.thorfinn.models.TaiEAgentModels;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TaiEAgentRunner {

    private final TaiEFlowAgent agent;

    public TaiEAgentRunner(ToolsConfig toolsConfig, String decompiledRootPath) {
        this.agent = new TaiEFlowAgent(TaiEAgentSetupFactory.build(toolsConfig), decompiledRootPath);
    }

    public TaiEAgentModels.FlowResponse analyze(TaiEAgentModels.FlowRequest request) {
        AgentOutput<TaiEAgentModels.FlowResponse> output = agent.execute(
                AgentInput.<TaiEAgentModels.FlowRequest>builder()
                        .request(request)
                        .build()
        );

        if (output == null) {
            throw new IllegalStateException("TaiE agent returned null output");
        }

        if (output.getError() != null && output.getError().getErrorType() != ErrorType.SUCCESS) {
            log.error("[TaiEAgentRunner] Agent failure type={} message={}",
                    output.getError().getErrorType(), output.getError().getMessage());
            log.error("[TaiEAgentRunner] Usage stats at failure: {}", output.getUsage());
            log.error("[TaiEAgentRunner] New messages at failure: {}", output.getNewMessages());
            log.error("[TaiEAgentRunner] All messages at failure: {}", output.getAllMessages());
            throw new IllegalStateException("TaiE agent failed: " + output.getError().getMessage());
        }

        if (output.getError() != null) {
            log.info("[TaiEAgentRunner] Agent completed with status={} message={}",
                    output.getError().getErrorType(), output.getError().getMessage());
        }

        TaiEAgentModels.FlowResponse response = output.getData();
        if (response == null) {
            throw new IllegalStateException("TaiE agent returned null response data");
        }

        return response;
    }
}
