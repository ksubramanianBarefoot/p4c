/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef MIDEND_COMMONINGPARSER_H_
#define MIDEND_COMMONINGPARSER_H_

#include <stack>
#include <algorithm> 
#include "ir/ir.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#define COMMON_HDR "_common_" // Need to ensure no other header uses this 
namespace P4 {

struct ParseStateInfo {
    cstring name = "P4ParseState";
    cstring firstHeaderExtracted = "";
    cstring lastHeaderExtracted = "";
    std::set<ParseStateInfo *> parents;
    std::set<ParseStateInfo *> children;
};

class CommonFields : public Transform, P4WriteContext {
	std::map<cstring, P4::ParseStateInfo *> &parserStates;
    std::map<cstring, IR::Type_Header *> &headers;
    std::map<cstring, IR::Type_Header *> newHeaders;
    std::map<cstring, std::set<ParseStateInfo *> *> headerExtractStates;
    std::map<cstring, IR::Type_Header *> modifiedHeaders;
    std::map<cstring, cstring> headerMap;
    std::map<cstring, std::vector<cstring> *> remappedFields;

    ParseStateInfo *curr = nullptr;
    int commonHdrNo = 0;


    int findCommonFields(IR::Type_Header *, IR::Type_Header *);
    IR::Type_Header *preorder(IR::Type_Header *) override;
    IR::PathExpression *preorder(IR::PathExpression *) override;
    IR::MethodCallExpression *preorder(IR::MethodCallExpression *) override;
    IR::ParserState *preorder(IR::ParserState *) override;
    IR::ParserState *postorder(IR::ParserState *) override;
    IR::P4Parser *postorder(IR::P4Parser *) override;
    IR::P4Program *postorder(IR::P4Program *) override;

    class ModifyHeaders;

 public:
    CommonFields(std::map<cstring, P4::ParseStateInfo *> *ps, 
    std::map<cstring, IR::Type_Header *> *hdrs) : 
    parserStates(*ps), headers(*hdrs) {
    	visitDagOnce = false;
        setName("CommonFields"); 
    }
};

class CommoningParser : public PassManager {
	std::map<cstring, P4::ParseStateInfo *> *parserStates;
    std::map<cstring, IR::Type_Header *> *headers;

 public:
    CommoningParser(ReferenceMap* refMap, TypeMap* typeMap) {
    	parserStates = new std::map<cstring, P4::ParseStateInfo *>;
    	headers = new std::map<cstring, IR::Type_Header *>;
    	passes.push_back(new TypeChecking(refMap, typeMap, true));
        passes.push_back(new CommonFields(parserStates, headers));
        setName("CommoningParser");
    }
};

}  // namespace P4

#endif /* MIDEND_COMMONINGPARSER_H_ */