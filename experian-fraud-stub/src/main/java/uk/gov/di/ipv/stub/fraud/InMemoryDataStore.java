package uk.gov.di.ipv.stub.fraud;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.stub.fraud.gateway.dto.response.IdentityVerificationResponse;
import uk.gov.di.ipv.stub.fraud.gateway.dto.response.Rule;

import java.util.HashMap;
import java.util.List;

import static uk.gov.di.ipv.stub.fraud.Util.getResourceAsStream;
import static uk.gov.di.ipv.stub.fraud.Util.mapFileToObject;

public class InMemoryDataStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryDataStore.class);
    private final HashMap<String, IdentityVerificationResponse> experianResponses = new HashMap<>();

    public InMemoryDataStore(ObjectMapper mapper) {
        init();
    }

    public IdentityVerificationResponse getResponse(final String id) {
        return experianResponses.get(id);
    }

    public IdentityVerificationResponse getResponseOrElse(
            final String id, final IdentityVerificationResponse alt) {
        return experianResponses.getOrDefault(id, alt);
    }

    public void addResponse(
            final String id, final IdentityVerificationResponse identityVerificationResponse) {
        experianResponses.put(id, identityVerificationResponse);
    }

    public void addResponse(final String id, final String identityVerificationResponse) {
        experianResponses.put(
                id,
                mapFileToObject(
                        getResourceAsStream(identityVerificationResponse),
                        IdentityVerificationResponse.class));
    }

    public boolean removeResponse(final String id) {
        IdentityVerificationResponse response = experianResponses.get(id);
        if (response != null) {
            experianResponses.remove(id);
            return true;
        } else {
            return false;
        }
    }

    private void init() {
        addResponse("AUTH1", "/GenericResponse/fraud-ex--auth1.json");
        addResponse("AUTH2", "/GenericResponse/fraud-ex--auth2.json");
        addResponse("NOAUTH", "/GenericResponse/fraud-ex--no-auth.json");
        addResponse("REFER", "/GenericResponse/fraud-ex--refer.json");

        addResponse("FARRELL", "/SpecificResponse/fraud-ex-ci1-farrell.json");
        addResponse("ARKIL", "/SpecificResponse/fraud-ex-ci1-arkil.json");
        addResponse("GILT", "/SpecificResponse/fraud-ex-ci2-gilt.json");
        addResponse("KENNEDY", "/SpecificResponse/fraud-ex-ci3-kennedy.json");

        addResponse("CI1", SerializationUtils.clone(experianResponses.get("REFER")));
        addResponse("CI2", SerializationUtils.clone(experianResponses.get("REFER")));
        addResponse("CI3", SerializationUtils.clone(experianResponses.get("REFER")));
        addResponse("CI4", SerializationUtils.clone(experianResponses.get("REFER")));
        addResponse("CI5", SerializationUtils.clone(experianResponses.get("REFER")));

        setRuleId("CI1", Config.CI1);
        setRuleId("CI2", Config.CI2);
        setRuleId("CI3", Config.CI3);
        setRuleId("CI4", Config.CI4);
        setRuleId("CI5", Config.CI5);
    }

    private void setRuleId(String ci, String... Ucode) {
        List<Rule> Rules =
                experianResponses
                        .get(ci)
                        .getClientResponsePayload()
                        .getDecisionElements()
                        .get(0)
                        .getRules();
        Rules.get(0).setRuleId(Ucode[0]);

        if (Ucode.length > 1) {
            for (int i = 1; i < Ucode.length; i++) {
                Rule newRule = new Rule();
                newRule.setRuleId(Ucode[i]);

                Rules.add(newRule);
            }
        }
    }
}
