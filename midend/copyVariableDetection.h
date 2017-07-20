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

#ifndef MIDEND_COPYVARIABLEDETECTION_H_
#define MIDEND_COPYVARIABLEDETECTION_H_

#include <stack>
#include <algorithm> 
#include "ir/ir.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/common/resolveReferences/referenceMap.h"

#define DF_NOCHANGE "###nochange###"
#define DF_UNDEFINED "###undefined###"
#define DF_INITIAL "###initial###"

namespace P4 {

/**
Local copy propagation and dead code elimination within a single pass.
This pass is designed to be run after all declarations have received unique
internal names.  This is important because the locals map uses only the
declaration name, and not the full path.

@pre
Requires expression types be stored inline in the expression
(obtained by running Typechecking(updateProgram = true)).

Requires that all declaration names be globally unique
(obtained by running UniqueNames).

Requires that all variable declarations are at the top-level control scope
(obtained using MoveDeclarations).
 */
cstring getVariableName(const IR::Expression *);

struct Dataflow {
    std::vector<const IR::Expression *> values;
};

struct VarInfo {
    bool                    local = false;
    bool                    live = false;
    const IR::Expression    *val = nullptr;
};

struct TableInfo {
    cstring name = "P4Table";
    std::set<cstring>       keyreads, actions;
    bool insideConditional = false;
    bool insideSwitch = false;
    bool harmless = false;
    int depth = 0;
    int ifId = 0;
    const IR::Expression *ifCondition = nullptr;
    bool dataflowComputed = false;
    std::set<TableInfo *> parents;
    std::set<TableInfo *> children;
    std::map<cstring, std::set<cstring> *> keyDataflows; 
    std::map<cstring, std::set<cstring> *> dataflows; 

};

struct FuncInfo {
    std::set<cstring>       reads, writes;
    // Straight line code in action; considering var = var statements
    std::map<cstring, cstring> dataflows;
    // Extended dataflow for parallel semantics, for e.g. parser
    std::map<cstring, std::set<cstring>> edataflows; 
};

class GenerateTableFlow : public ControlFlowVisitor, Inspector, P4WriteContext {
    std::set<cstring>                   variables;
    std::map<cstring, P4::TableInfo*>        &tables;
    std::map<cstring, P4::FuncInfo*>         &actions;
    std::map<cstring, P4::FuncInfo>         &methods;

    TableInfo                           *inferForTable = nullptr;
    FuncInfo                            *inferForFunc = nullptr;
    TableInfo                           *curr = nullptr;
    TableInfo                           *start = nullptr;
    bool insideSwitch = false;
    std::stack<int> ifIds;
    std::stack<const IR::Expression *> ifConditions;
    GenerateTableFlow *clone() const override { return new GenerateTableFlow(*this); }
    void flow_merge(Visitor &) override;

    bool preorder(const IR::IfStatement *) override;
    void postorder(const IR::IfStatement *) override;
    bool preorder(const IR::SwitchStatement *) override;
    bool preorder(const IR::MethodCallExpression *) override;
    bool preorder(const IR::P4Program *) override;
    void apply_table(TableInfo *);
    bool checkHarmless(TableInfo *);
    void computeDataflows(P4::TableInfo *);
    std::set<cstring> *mergeDataflow(std::set<cstring> *, std::set<cstring> *);
    std::set<cstring> *applyDataflow(std::set<cstring> *, std::set<cstring> *);
    void printTableGraph(TableInfo *tbl, std::set<TableInfo *>& visited);
    void printTableGraph();
    GenerateTableFlow(const GenerateTableFlow &) = default;

 public:
    GenerateTableFlow(std::map<cstring, P4::TableInfo*> *tbls,
        std::map<cstring, P4::FuncInfo*> *acts, std::map<cstring, P4::FuncInfo> *mthds) :
        tables(*tbls), actions(*acts), methods(*mthds)  {
        curr = new TableInfo;
        start = curr;
        curr->name = "StartTable";
        curr->depth = 0; 
        setName("GenerateTableFlow");
    }
};



class ExtractVariables : public Inspector, P4WriteContext {
    std::map<cstring, P4::Dataflow>     &dataflows;
    std::map<cstring, TableInfo*>        &tables;
    std::map<cstring, FuncInfo*>         &actions;
    std::map<cstring, FuncInfo>         &methods;
    TableInfo                           *inferForTable = nullptr;
    FuncInfo                            *inferForFunc = nullptr;

    // void visit_local_decl(const IR::Declaration_Variable *);
    bool preorder(const IR::AssignmentStatement *) override;
    // bool preorder(const IR::Declaration_Variable *) override;
    bool preorder(const IR::P4Action *) override;
    void postorder(const IR::P4Action *) override;
    bool preorder(const IR::Function *) override;
    void postorder(const IR::Function *) override;
    bool preorder(const IR::P4Table *) override;
    void postorder(const IR::P4Table *) override;
    void postorder(const IR::Member *) override;
    bool preorder(const IR::P4Control *) override;
    bool preorder(const IR::P4Parser *) override;
    void postorder(const IR::P4Parser *) override;

    void prepareDataflow(P4::TableInfo *);

 public:
    ExtractVariables(std::map<cstring, P4::Dataflow> *dfs, std::map<cstring, P4::TableInfo*> *tbls,
        std::map<cstring, P4::FuncInfo*> *acts, std::map<cstring, P4::FuncInfo> *mthds) :
        dataflows(*dfs), tables(*tbls), actions(*acts), methods(*mthds)  {
        visitDagOnce = true;
        setName("ExtractVariables");
    }
};

class ModifyHarmlessTable : public Transform {
    std::map<cstring, TableInfo*>        &tables;
    std::map<cstring, FuncInfo*>         &actions;
    std::map<cstring, FuncInfo>         &methods;
    std::set<const IR::Statement *> harmlessTables;
    bool checkDownstreamTables(P4::TableInfo *, P4::TableInfo *, std::map<P4::TableInfo *, bool> *);
    bool checkUpstreamTables(P4::TableInfo *, P4::TableInfo *);
    bool checkHarmless(P4::TableInfo *);
    IR::Statement *preorder(IR::IfStatement *) override;
    const IR::Statement *postorder(IR::IfStatement *) override;
    IR::MethodCallExpression *postorder(IR::MethodCallExpression *) override;
    IR::Statement *postorder(IR::MethodCallStatement *) override;

 public:
    ModifyHarmlessTable(std::map<cstring, P4::TableInfo*> *tbls, 
        std::map<cstring, P4::FuncInfo*> *acts, std::map<cstring,
        P4::FuncInfo> *mthds) :
        tables(*tbls), actions(*acts), methods(*mthds)  {
        setName("ModifyHarmlessTable");
    }
};

class DetectCopy  : public Transform {
    std::map<cstring, TableInfo*>        &tables;
    std::map<cstring, FuncInfo*>         &actions;
    std::map<cstring, FuncInfo>         &methods;
    std::set<cstring> copyCandidates; 
    std::set<cstring> nonCopyCandidates;
    bool printTbl;

    IR::AssignmentStatement *preorder(IR::AssignmentStatement *) override;
    IR::Expression *postorder(IR::Expression *) override;
    IR::P4Control *preorder(IR::P4Control *) override;
    IR::P4Table *preorder(IR::P4Table *) override;
    IR::P4Program *postorder(IR::P4Program *) override;

 public:
    DetectCopy(std::map<cstring, P4::TableInfo*> *tbls, 
        std::map<cstring, P4::FuncInfo*> *acts, std::map<cstring,
        P4::FuncInfo> *mthds) :
        tables(*tbls), actions(*acts), methods(*mthds)  {
        setName("DetectCopy");
    }
};


class CopyVariableDetection : public PassManager {
    std::map<cstring, P4::Dataflow>     dataflows;
    std::map<cstring, TableInfo*>        tables;
    std::map<cstring, FuncInfo*>         actions;
    std::map<cstring, FuncInfo>         methods;

 public:
    CopyVariableDetection(ReferenceMap* refMap, TypeMap* typeMap) {
        passes.push_back(new TypeChecking(refMap, typeMap, true));
        dataflows = *(new  std::map<cstring, P4::Dataflow>);
        tables = *(new std::map<cstring, P4::TableInfo*>);
        actions = *(new std::map<cstring, P4::FuncInfo*>);
        methods = *(new std::map<cstring, P4::FuncInfo>);
        passes.push_back(new ExtractVariables(&dataflows, &tables, &actions, &methods));
        passes.push_back(new GenerateTableFlow(&tables, &actions, &methods));
        // passes.push_back(new ModifyHarmlessTable(&tables, &actions, &methods));
        passes.push_back(new DetectCopy(&tables, &actions, &methods));
        setName("CopyVariableDetection");
    }
};

}  // namespace P4

#endif /* MIDEND_COPYVARIABLEDETECTION_H_ */
