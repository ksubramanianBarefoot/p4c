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

#include "copyVariableDetection.h"
#include "has_side_effects.h"
#include "expr_uses.h"

namespace P4 {

cstring getVariableName(const IR::Expression *expr) {
    // Variable Name
    if (auto var = expr->to<IR::PathExpression>()) {
        return var->path->name;
    }
    // Metadata/Header field
    if (auto var = expr->to<IR::Member>()) {
        return var->toString();
    } else {
        return "";
    }
}

bool GenerateTableFlow::preorder(const IR::P4Program *pp) {
    const IR::P4Control *ingress, *egress;
    const IR::P4Parser *parser;
    for (auto decl : pp->declarations) {
        if (auto ctrl = decl->to<IR::P4Control>()) {
            if (ctrl->name == "ingress") ingress = ctrl;
            if (ctrl->name == "egress") egress = ctrl;
        }
        if (auto ctrl = decl->to<IR::P4Parser>()) {
            parser = ctrl;
        }
    }
    // Add parser "table" to table flow.
    BUG_CHECK(tables.count("parser") > 0, "Parser table not instantiated");
    TableInfo *parsertbl = tables["parser"];
    curr->children.insert(parsertbl);
    parsertbl->parents.insert(curr);
    parsertbl->depth = 1;
    curr = parsertbl;

    // Visit ingress and egress in that order
    LOG3("Visiting Ingress");
    if (ingress) visit(ingress, "ingress");
    LOG3("Visiting Egress");
    if (egress) visit(egress, "egress");
    /* Compute dataflow for the table flow graph */
    for (auto var : variables) {
        start->dataflows[var] = new std::set<cstring>();
        // FIXME - Handle initial values  defined in declarations?
        start->dataflows[var]->insert(DF_INITIAL);
    }

    start->dataflowComputed = true;
    for (auto child : start->children) {
        computeDataflows(child);
    } 
    return false;
}

bool GenerateTableFlow::preorder(const IR::IfStatement *ifs) {
    ifIds.push(ifs->id);
    ifConditions.push(ifs->condition);    
    return true;
}
void GenerateTableFlow::postorder(const IR::IfStatement *ifs) {
    ifIds.pop();
    ifConditions.pop();
}

bool GenerateTableFlow::preorder(const IR::SwitchStatement *ss) {
    ifIds.push(ss->id);
    ifConditions.push(ss->expression);    
    
    // Generate Table Flow for switch-statement  
    visit(ss->expression);
    insideSwitch = true;
    bool defaultCase = false;
    auto switchParentNode = curr; 
    std::set<TableInfo*> caseflows;
    for (auto switchCase : ss->cases) {
        if (switchCase->label->to<IR::DefaultExpression>()) defaultCase = true;
        curr = switchParentNode;
        visit(switchCase);
        caseflows.insert(curr);
    }
    if (!defaultCase) caseflows.insert(switchParentNode);

    // Merging the different switch blocks
    auto switchConvergeTable = new TableInfo;
    switchConvergeTable->name = "switchConvergeTable";
    for (auto tbl : caseflows) {
        switchConvergeTable->parents.insert(tbl);
        tbl->children.insert(switchConvergeTable);
        LOG4("Adding" << tbl->name << " switchConvergeTable");
        switchConvergeTable->depth = std::max(switchConvergeTable->depth, tbl->depth + 1);
    }
    switchConvergeTable->ifId = ifIds.top(); 
    curr = switchConvergeTable;
    ifIds.pop();
    ifConditions.pop();
    insideSwitch = false;
    return false;
}

bool GenerateTableFlow::preorder(const IR::MethodCallExpression *mc) {
    LOG3("In mc post" << curr->name << " " << mc->method);
    if (auto mem = mc->method->to<IR::Member>()) {
        if (auto obj = mem->expr->to<IR::PathExpression>()) {
            if (tables.count(obj->path->name)) {
                LOG3("table apply method call " << mc->method);
                auto tbl = tables[obj->path->name];
                for (auto act : tbl->actions) {
                    auto action = actions[act];
                    for (auto var : action->reads) {
                        if (variables.count(var) == 0) {
                            variables.insert(var);
                        }
                    }
                    for (auto var : action->writes) {
                        if (variables.count(var) == 0) {
                            variables.insert(var);
                        }
                    }  
                }
                BUG_CHECK(tbl->depth <= 0 || tbl->depth >= curr->depth, "Adding edge back to some parent");
                BUG_CHECK(tbl != curr, "Adding a self loop");
                tbl->parents.insert(curr);
                if (curr) {
                    curr->children.insert(tbl);
                    tbl->depth = curr->depth + 1;
                    LOG4("Adding" << curr->name << " " << tbl->name);
                }
                curr = tbl;
                if (!curr) return true;
                auto insideIf = findContext<IR::IfStatement>();
                if (insideIf || insideSwitch) {
                    curr->insideConditional = insideIf;  // Table can be potentially harmless
                    if (insideSwitch) curr->insideSwitch = true;
                    BUG_CHECK(!ifIds.empty(), "If stack must not be empty"); 
                    curr->ifId = ifIds.top();
                    curr->ifCondition = ifConditions.top();
                }
            }
        }
    }
    return true;
}

void GenerateTableFlow::flow_merge(Visitor &a_) {
    auto &a = dynamic_cast<GenerateTableFlow &>(a_);
    if (curr->name == a.curr->name) {
        // No need to merge
        return;
    } else {
        // Converge the if-else to dummy table.
        LOG4("Merging" << curr->name << a.curr->name);
        auto ifConvergeTable = new TableInfo;
        ifConvergeTable->name = "ifConvergeTable" + std::to_string(ifIds.top());
        ifConvergeTable->parents.insert(curr);
        ifConvergeTable->parents.insert(a.curr);
        curr->children.insert(ifConvergeTable);
        a.curr->children.insert(ifConvergeTable);
        ifConvergeTable->ifId = ifIds.top(); 
        ifConvergeTable->depth = std::max(curr->depth + 1, a.curr->depth + 1);
        curr = ifConvergeTable;
    }
}


void GenerateTableFlow::computeDataflows(P4::TableInfo *tbl) {
    if (tbl->dataflowComputed) return;
    LOG3("compute df" << tbl->name);
    // Check if all parents' dataflows have been computed 
    for (auto parent : tbl->parents) {
        if (!parent->dataflowComputed) 
            return;
    }
    for (auto var : variables) {
        auto dataflow = new std::set<cstring>;
        // merge parents' dataflow
        for (auto parent : tbl->parents)
            dataflow = mergeDataflow(dataflow, parent->dataflows[var]);
        tbl->keyDataflows[var] = new std::set<cstring>(*dataflow);
        // apply this table's dataflow
        if (tbl->dataflows.count(var) > 0)
            dataflow = applyDataflow(dataflow, tbl->dataflows[var]);
        tbl->dataflows[var] = dataflow;
        if (tbl->name == "parser") 
            LOG3("Dataflow" << var << " " << *dataflow);
        LOG4("Dataflow" << var << " " << *dataflow);
    }
    tbl->dataflowComputed = true;
    for (auto child : tbl->children) {
        computeDataflows(child);
    } 
}

std::set<cstring> *GenerateTableFlow::mergeDataflow(
    std::set<cstring> *df1, std::set<cstring> *df2) {
    if (df1->count(DF_UNDEFINED) + df2->count(DF_UNDEFINED) > 0) {
        df1->clear();
        df1->insert(DF_UNDEFINED);
    } else {
        for (auto val : *df2) 
            df1->insert(val);
    }
    return df1;
}

std::set<cstring> *GenerateTableFlow::applyDataflow(
    std::set<cstring> *df1, std::set<cstring> *df2) {
    if (df2->count(DF_NOCHANGE) == 0) 
        df1->clear();
    for (auto val : *df2) {
        if (val != DF_NOCHANGE)
            df1->insert(val);
    }
    if (df1->count(DF_UNDEFINED) > 0) {
        df1->clear();
        df1->insert(DF_UNDEFINED);
    }
    return df1; 
}

void GenerateTableFlow::printTableGraph() {
    std::set<TableInfo *> visited = *(new std::set<TableInfo *>);
    printTableGraph(start, visited);
}

void GenerateTableFlow::printTableGraph(TableInfo *tbl, std::set<TableInfo *>& visited) {
    if (!tbl) return;
    if (visited.count(tbl) > 0) return;
    visited.insert(tbl);
    LOG2("Table Info: " << tbl->name << " Depth=" << tbl->depth << " If id=" << tbl->ifId);
    cstring parents = "Parents=(";
    for (TableInfo *parent: tbl->parents) {
        parents = parents + parent->name + ",";
    }
    LOG2(parents);
    cstring children = "Children=(";
    for (TableInfo *child: tbl->children) {
        children = children + child->name + ",";
    }
    LOG2(children);
    for (TableInfo *child: tbl->children) {
        printTableGraph(child, visited);
    }
}

// void ExtractVariables::visit_local_decl(const IR::Declaration_Variable *var) {
//     LOG4("Visiting " << var);
// }

// bool ExtractVariables::preorder(const IR::Declaration_Variable *var) {
//     visit_local_decl(var);
//     return true;
// }

bool ExtractVariables::preorder(const IR::P4Table *tbl) {
    BUG_CHECK(!inferForTable, "corrupt internal data struct");
    if (tables.count(tbl->name) == 0) 
        tables[tbl->name] = new TableInfo;
    inferForTable = tables[tbl->name];
    inferForTable->name = tbl->name;
    inferForTable->keyreads.clear();
    for (auto ale : tbl->getActionList()->actionList) {
        if (!cstring(ale->getPath()->name).startsWith(cstring("NoAction"))) 
            inferForTable->actions.insert(ale->getPath()->name);
    }
    return true;
}

void ExtractVariables::postorder(const IR::P4Table *tbl) {
    BUG_CHECK(inferForTable, "corrupt internal data struct");
    LOG2("table " << tbl->name << " reads=" << inferForTable->keyreads <<
         " actions=" << inferForTable->actions);
    prepareDataflow(inferForTable);
    inferForTable = nullptr;
}

void ExtractVariables::prepareDataflow(P4::TableInfo* tbl) {
    std::set<cstring> vars; 
    for (auto act : tbl->actions) {
        auto action = actions[act];
        for (auto var : action->writes) {
            vars.insert(var);
        }
    }
    for (cstring var : vars) {
        std::set<cstring> *values = new std::set<cstring>; 
        for (auto act : tbl->actions) {
            auto action = actions[act];
            if (action->edataflows.count(var) > 0) {
                for (cstring val : action->edataflows[var]) {
                    values->insert(val);
                }
                values->insert(DF_NOCHANGE);
            } else if (action->dataflows.count(var) > 0) {
                values->insert(action->dataflows[var]);   
            } else {
                values->insert(DF_NOCHANGE);
            }
        }
        // Undefined
        if (values->count(DF_UNDEFINED) > 0) {
            values->clear();
            values->insert(DF_UNDEFINED);
        }
        tbl->dataflows[var] = values;
        LOG1("DF " << var << " " << *values);
        // LOG3("DF" << var);
        // for (auto val : *values) {
        //     LOG3(val);
        // }
    }
}

bool ExtractVariables::preorder(const IR::P4Action *act) {
    BUG_CHECK(!inferForFunc, "corrupt internal data struct");
    if (cstring(act->name).startsWith(cstring("NoAction"))) return false;
    if (actions.count(act->name) == 0) 
        actions[act->name] = new FuncInfo;
    inferForFunc = actions[act->name];
    LOG2("ExtractVariables working on action " << act->name);
    LOG4(act);
    return true;
}

void ExtractVariables::postorder(const IR::P4Action *act) {
    BUG_CHECK(inferForFunc == actions[act->name], "corrupt internal data struct");
    LOG3("ExtractVariables finished action " << act->name);
    LOG2("reads=" << inferForFunc->reads << " writes=" << inferForFunc->writes);
    inferForFunc = nullptr;
}

bool ExtractVariables::preorder(const IR::Function *fn) {
    BUG_CHECK(!inferForFunc, "corrupt internal data struct");
    auto name = findContext<IR::Declaration_Instance>()->name + '.' + fn->name;
    inferForFunc = &methods[name];
    LOG2("ExtractVariables working on function " << name);
    LOG4(fn);
    return true;
}

void ExtractVariables::postorder(const IR::Function *fn) {
    auto name = findContext<IR::Declaration_Instance>()->name + '.' + fn->name;
    BUG_CHECK(inferForFunc == &methods[name], "corrupt internal data struct");
    LOG3("ExtractVariables finished function " << name);
    LOG4("reads=" << inferForFunc->reads << " writes=" << inferForFunc->writes);
    inferForFunc = nullptr;
}

void ExtractVariables::postorder(const IR::Member *member) {
    if (findContext<IR::Member>()) {
        return;
    }
    if (inferForTable) {
        const Visitor::Context *ctxt = nullptr;
        if (findContext<IR::KeyElement>(ctxt) && ctxt->child_index == 1)
            inferForTable->keyreads.insert(P4::getVariableName(member)); }
    if (isWrite()) {
        if (inferForFunc)
            inferForFunc->writes.insert(P4::getVariableName(member));
        if (isRead() || findContext<IR::MethodCallExpression>()) {
            /* If this is being used as an 'out' param of a method call, its not really
             * read, but we can't dead-code eliminate it without eliminating the entire
             * call, so we mark it as live.  Unfortunate as we then won't dead-code
             * remove other assignmnents. */
            if (inferForFunc)
                inferForFunc->reads.insert(P4::getVariableName(member)); }
    } else {
        if (inferForFunc)
            inferForFunc->reads.insert(P4::getVariableName(member));
    }
}

bool ExtractVariables::preorder(const IR::AssignmentStatement *as) {
    // visit the source subtree first, before the destination subtree
    // make sure child indexes are set properly so we can detect writes -- these are the
    // extra arguments to 'visit' in order to make introspection vis the Visitor::Context
    // work.  Normally this is all managed by the auto-generated visit_children methods,
    // but since we're overriding that here AND P4WriteContext cares about it (that's how
    // it determines whether something is a write or a read), it needs to be correct
    // This is error-prone and fragile
    cstring lname = P4::getVariableName(as->left);
    cstring rname = P4::getVariableName(as->right);
    if (inferForFunc && lname != "") {
        cstring dfv;
        if (rname != "" && (rname.startsWith(cstring("hdr")) || rname.startsWith(cstring("meta")))) {
            dfv = rname;
        } else {
            dfv = DF_UNDEFINED;
        }
        inferForFunc->dataflows[lname] = dfv;
        if (inferForTable && inferForTable->name == "parser") {
            // Use parallel semantics for parser
            inferForFunc->edataflows[lname].insert(dfv);
        }
    }   
    visit(as->right, "right", 1);
    visit(as->left, "left", 0);
    return true;
}

bool ExtractVariables::preorder(const IR::P4Control *ctrl) {
    return true;
}

bool ExtractVariables::preorder(const IR::P4Parser *parser) {
    TableInfo *parsertbl = new TableInfo;
    parsertbl->name = "parser";
    tables["parser"] = parsertbl;
    inferForTable = parsertbl;
    actions["parser"] = new FuncInfo;
    parsertbl->actions.insert("parser");
    inferForFunc = actions["parser"];
    return true;
}

void ExtractVariables::postorder(const IR::P4Parser *parser) {
    LOG2("Parser reads=" << inferForFunc->reads << " writes=" << inferForFunc->writes);
    prepareDataflow(inferForTable);
    inferForFunc = nullptr;
    inferForTable = nullptr;
}

bool ModifyHarmlessTable::checkHarmless(P4::TableInfo *tbl) {
    /* For downstream tables, if no table reads what tbl has
     * written to, then tbl is harmless.
     * For upstream tables inside the if-statement, if
     * no tables write to fields which are read by tbl,
     * tbl is harmless.
     * FIXME - Improve algorithm */
    if (tbl->insideConditional) {
        // Check if table does not write into packet headers/meters/registers
        for (auto act : tbl->actions) {
            for (auto varw : actions[act]->writes) {
            // if varw contains hdr... 
                if (varw.startsWith(cstring("hdr"))) {
                    // Lasting effects 
                    return false;
                }
            }
        }
        // FIXME - Check extern functions inside actions

        // Check if table does not conflict with the if-condition
        if (hasSideEffects(tbl->ifCondition)) return false;
         for (auto act : tbl->actions) {
            for (auto varw : actions[act]->writes) {
                if (exprUses(tbl->ifCondition, varw)) {
                    return false;  
                }
            }
        }

        // Table is in egress pipeline and inside an if-block
        bool upstream = false;
        if (tbl->parents.size() > 0) 
            upstream = checkUpstreamTables(tbl, *(tbl->parents.begin()));
        if (upstream) {
            // find first downstream table outside if-block
            auto curr = *(tbl->children.begin());
            while (curr && curr->ifId == tbl->ifId && curr->ifId != 0) {
                LOG2(curr->name);
                curr = *(curr->children.begin());

            }
            std::map<P4::TableInfo *, bool> *checkConflict = new std::map<P4::TableInfo *, bool>;
            bool downstream = checkDownstreamTables(tbl, curr, checkConflict);
            if (downstream) {
                return true;
            }
        }
    }
    return false;
}                                        

bool ModifyHarmlessTable::checkDownstreamTables(P4::TableInfo *tbl, P4::TableInfo *curr, 
    std::map<P4::TableInfo *, bool> *checkConflict) {
    if (!tbl || !curr || checkConflict->count(curr) > 0) return true; 
    LOG3("Check D conflict" << tbl->name << " " << curr->name << " " << tbl->depth << " " << curr->depth);
    // Check to see if curr and tbl conflict
    // recursively, check curr's children
    for (auto act1 : tbl->actions) {
        for (auto act2 : curr->actions) {
            // act1 writes are not read by act2
            for (auto varw : actions[act1]->writes) {
                if (actions[act2]->reads.count(varw) > 0) {
                    LOG4("D-Conflict between " << tbl->name << " " << curr->name);
                    return false;
                }
            }
        }
        // act1 writes are not read by curr table keys 
        for (auto varw : actions[act1]->writes) {
            if (curr->keyreads.count(varw) > 0) {
                LOG4("D-Conflict between " << tbl->name << " " << curr->name);
                return false;
            }
        }
    }
    (*checkConflict)[curr] = true;
    // Explore and check children recursively
    bool noConflict = true;
    for (auto child : curr->children) {
        if (child) noConflict = noConflict & checkDownstreamTables(tbl, child, checkConflict);
        if (!noConflict) return false;
    }
    return noConflict;
}

bool ModifyHarmlessTable::checkUpstreamTables(P4::TableInfo *tbl, P4::TableInfo *curr) {
    // Check if curr is outside if block (will have different if ids)
    LOG3("Check U conflict" << tbl->name << " " << curr->name);
    if (curr->ifId != tbl->ifId)
        return true;
    // Check to see if curr and tbl conflict
    // recursively, check curr's parents
    for (auto act1 : tbl->actions) {
        for (auto act2 : curr->actions) {
            // act1 reads are not written by act2
            for (auto varr : actions[act1]->reads) {
                if (actions[act2]->writes.count(varr) > 0) {
                    LOG4("U-Conflict between " << tbl->name << " " << curr->name);
                    return false;
                }
            }
        }
    }
    // Explore and check parents recursively
    bool noConflict = true;
    for (auto parent : curr->parents) {
        noConflict = noConflict & checkUpstreamTables(tbl, parent);
    }
    return noConflict;
}

IR::Statement *ModifyHarmlessTable::preorder(IR::IfStatement *ifs) {
    // FIXME -- nesting ifs
    harmlessTables.clear();
    return ifs;
}

const IR::Statement *ModifyHarmlessTable::postorder(IR::IfStatement *ifs) {
    if (harmlessTables.size() > 0) {
        // harmless tables detected, move to outside if block
        auto bs = new IR::BlockStatement();
        for (auto tbl : harmlessTables) {
            if (tbl) bs->components.push_back(tbl->to<const IR::StatOrDecl>());
        }
        LOG3("here" << ifs);
        if (ifs) bs->components.push_back(ifs->to<const IR::StatOrDecl>());
        harmlessTables.clear();
        return bs->to<const IR::Statement>();
    }
    return ifs->to<const IR::Statement>();
}

IR::MethodCallExpression *ModifyHarmlessTable::postorder(IR::MethodCallExpression *mc) {
    if (auto mem = mc->method->to<IR::Member>()) {
        if (auto obj = mem->expr->to<IR::PathExpression>()) {
            if (tables.count(obj->path->name)) {
                LOG3("table apply method call " << mc->method);
                // Check if table is harmless.
                bool harmless = checkHarmless(tables[obj->path->name]);
                if (harmless) {
                    LOG1("table apply method call " << mc->method << "is harmless");
                    harmlessTables.insert((new IR::MethodCallStatement(mc))->to<const IR::Statement>());
                    return nullptr;
                }
            }
        }
    }
    return mc;
}

IR::Statement *ModifyHarmlessTable::postorder(IR::MethodCallStatement *mc) {
    if (!mc->methodCall) 
        return new IR::EmptyStatement();
    return mc;
}

IR::AssignmentStatement *DetectCopy::preorder(IR::AssignmentStatement *as) {
    // visit(as->right, "right", 0);
    return as;
}

IR::Expression *DetectCopy::postorder(IR::Expression *expr) {
    TableInfo* tblinfo = nullptr;
    auto parser = findContext<IR::P4Parser>();
    auto table = findContext<IR::P4Table>();
    if (parser) {
        tblinfo = tables["parser"];
    } else if (table) {
        tblinfo = tables[table->name];
    }

    if (tblinfo != nullptr) {
        std::set<cstring> *dataflow = nullptr;
        // Check to see if key expr to another field. 
        cstring var = P4::getVariableName(expr);
        if (var.startsWith(cstring("meta"))) {  
            if (findContext<IR::KeyElement>() != nullptr && tblinfo->keyDataflows.count(var) > 0) {
                dataflow = tblinfo->keyDataflows[var];
            } else if (tblinfo->dataflows.count(var) > 0) {
                dataflow = tblinfo->dataflows[var];
            }

            if (dataflow != nullptr) {
                // BUG_CHECK(tblinfo->keyDataflows[var, "Dataflow not instantiated, not possible");
                if (dataflow->count(DF_UNDEFINED) == 0) {
                     if (!printTbl) {
                        LOG1("Table is " << tblinfo->name);
                        printTbl = true;
                    }
                    LOG1(var << " values=" << *dataflow);
                }
                if ((dataflow->size() == 1 && dataflow->count(DF_UNDEFINED) == 0) || 
                    (dataflow->size() == 2 && dataflow->count(DF_INITIAL) == 1)) {
                    if (nonCopyCandidates.count(var) == 0) {
                        // var is a copy candidate. 
                        copyCandidates.insert(var);
                    } 
                } else {  
                    // var is not a copy candidate
                    nonCopyCandidates.insert(var);
                    copyCandidates.erase(var);
                }
            }
        }
    }
    return expr;
}

IR::P4Table *DetectCopy::preorder(IR::P4Table *tbl) {
    printTbl = false;
    return tbl;
}

IR::P4Control *DetectCopy::preorder(IR::P4Control *ctrl) {
    return ctrl;
}

IR::P4Program *DetectCopy::postorder(IR::P4Program *p4p) {
    LOG1("Copy candidates are " << copyCandidates);
    return p4p;
} 

}  // namespace P4
