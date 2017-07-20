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

#include "commoningParser.h"

namespace P4 {


class CommonFields::ModifyHeaders : public Transform {
    CommonFields &self;
   	cstring hdrName;
   	cstring newField = "";

    IR::P4Program *preorder(IR::P4Program *p4p) override {
    	if (self.newHeaders.count(hdrName) > 0) {
    		// Add new header to program
    		for (auto it = p4p->declarations.begin(); it < p4p->declarations.end(); ++it) {
    			const IR::Type_Header *hdr = (*it)->to<IR::Type_Header>();
	    		if (hdr && hdrName.startsWith(hdr->name)) {
	    			p4p->declarations.insert(it, self.newHeaders[hdrName]);
	    			break;
	    		}
	    	}
    	} else if (self.modifiedHeaders.count(hdrName) > 0) { 
    		// Replace the modified header
	    	for (auto it = p4p->declarations.begin(); it < p4p->declarations.end(); ++it) {
	    		const IR::Type_Header *hdr = (*it)->to<IR::Type_Header>();
	    		if (hdr && hdr->name == hdrName) {
	    			p4p->declarations.replace(it, self.modifiedHeaders[hdrName]);
	    			break;
	    		}
	    	}
    	}
    	return p4p;
    }

    IR::Type_Struct *preorder(IR::Type_Struct *ts) override {
    	if (ts->name == "headers" && self.newHeaders.count(hdrName) > 0) {
    		IR::StructField *newHdrDef = new IR::StructField(IR::ID(hdrName + "_in_hdr"), new IR::Type_Name(new IR::Path(IR::ID(hdrName))));
    		ts->fields.push_back(newHdrDef);
    	}
    	return ts;
    }

	IR::ParserState *postorder(IR::ParserState *ps) {
		if (self.headerExtractStates.count(hdrName) > 0) {
			if (self.headerExtractStates[hdrName]->count(self.parserStates[ps->name]) > 0) {
				// Add packet extract to components.
				IR::Member *arg = new IR::Member(new IR::PathExpression(new IR::Path("hdr")), 
					IR::ID(hdrName + "_in_hdr"));
				IR::Vector<IR::Expression> *arguments = new IR::Vector<IR::Expression>();
				arguments->push_back(arg);
				IR::Member *func = new IR::Member(new IR::PathExpression(new IR::Path("packet")), 
					IR::ID("extract"));
				IR::MethodCallExpression *me = new IR::MethodCallExpression(func, arguments);
				ps->components.insert(ps->components.begin(), new IR::MethodCallStatement(me));
			}
		}
		return ps;
	}

	IR::Member *preorder(IR::Member *mem) {
		if (mem->expr->type->to<IR::Type_Header>()) {
			cstring currHdrName = mem->expr->type->to<IR::Type_Header>()->name;
			LOG3("l1 " << currHdrName << self.headerMap[currHdrName] << " " << hdrName);
			if (self.headerMap.count(currHdrName) > 0 && 
				self.headerMap[currHdrName] == hdrName) {
				IR::Type_Header *newHdr = self.newHeaders[hdrName];
				cstring field = mem->member;
					// Check if field is in the new common header
				for (int pos = 0; pos < self.remappedFields[currHdrName]->size(); ++pos) {
					if ((*self.remappedFields[currHdrName])[pos] == field) { 
						newField = newHdr->fields[pos]->name;
						// Belongs to common field. Replace header.
						LOG1("Replacing " << mem->member << " for header " << currHdrName << " nF is " << hdrName <<newField);
						mem->expr = new IR::Member(mem->expr->to<IR::Member>()->expr, IR::ID(hdrName + "_in_hdr"));
						mem->member = IR::ID(newField);
					}
				}
			} 
		}
		return mem;
	}

	// IR::Member *postorder(IR::Member *mem) {
	// 	if(mem->member == "typeCode") {
	// 		LOG1("TypeCode");
	// 		dbprint(mem);
	// 	}
	// 	if (!mem->type->to<IR::Type_Header>() && newField != "") {
	// 		mem->member = IR::ID(newField);
	// 		newField = "";
	// 		LOG1("Replacing " << mem->member << " for header " << hdrName << newField);
	// 	} 
	// 	return mem;
	// }

 public:
    ModifyHeaders(CommonFields &self, cstring name) : self(self), hdrName(name) {}
};

int CommonFields::findCommonFields(IR::Type_Header *hdr1, IR::Type_Header *hdr2) {
	if (!hdr1 || !hdr2) return 0;
    IR::IndexedVector<IR::StructField> commonFields;
    int pos = 0;
    for (const IR::StructField *hf1 : hdr1->fields) {
        if (pos < hdr2->fields.size()) {
            const IR::StructField *hf2 = hdr2->fields[pos];
            bool isEqual = true;
            if (hf1->type->to<IR::Type_Varbits>() || hf2->type->to<IR::Type_Varbits>()) {
                isEqual = false;
            }
            // Header fields types must be Type_Bits or Type_Varbits
            if (hf1->type->to<IR::Type_Bits>()->size != hf2->type->to<IR::Type_Bits>()->size) {
                isEqual = false;
            }  
            if (isEqual) {
            	LOG3("Common field " << hdr1->name << " " << hdr2->name << " is " << hf1->name);
            	commonFields.push_back(hf1);
            }
            else break;
        }
        pos = pos + 1;
    }
    return commonFields.size();
}

IR::ParserState *CommonFields::preorder(IR::ParserState *ps) {
	if (parserStates.count(ps->name) == 0)  {
		parserStates[ps->name] = new ParseStateInfo;
		parserStates[ps->name]->name = ps->name;
	}
	curr =  parserStates[ps->name];
	LOG3("Parser State =" << ps->name);
	return ps;
}

IR::ParserState *CommonFields::postorder(IR::ParserState *ps) {
	curr = nullptr;
	return ps;
}


IR::PathExpression *CommonFields::preorder(IR::PathExpression *pe) {
	if (findContext<IR::SelectCase>() || getContext()->node->is<IR::ParserState>()) {
		// Parser state transition
		if (parserStates.count(pe->path->name) == 0)  {
			parserStates[pe->path->name] = new ParseStateInfo;
			parserStates[pe->path->name]->name = pe->path->name;
		}
		curr->children.insert(parserStates[pe->path->name]);
		parserStates[pe->path->name]->parents.insert(curr);
		LOG3("Parser Transition " << curr->name << "->" << pe->path->name);
	}
	return pe;
}

IR::Type_Header *CommonFields::preorder(IR::Type_Header *hdr) {
    cstring hdrName = cstring(hdr->name);
    LOG2("hdr" << hdrName);
    headers[hdrName] = hdr;
    return hdr;
}

IR::MethodCallExpression *CommonFields::preorder(IR::MethodCallExpression *mc) {
	const IR::Member *mem = mc->method->to<IR::Member>();
	if (mem && cstring(mem->member) == "extract") {
		// Header extraction method
		int pos = 0;
		for (auto type: *(mc->typeArguments)) {
			if (type->to<IR::Type_Name>()) {
				if (pos == 0) curr->firstHeaderExtracted = type->to<IR::Type_Name>()->path->name;
				curr->lastHeaderExtracted = type->to<IR::Type_Name>()->path->name;
				LOG3("Header extracted is " << curr->lastHeaderExtracted);
				++pos;
			}
		}
	} 
	return mc;
}

IR::P4Parser *CommonFields::postorder(IR::P4Parser *parser) {
	for (auto state : parserStates) {
		/* find common headers in the children states */
		if (state.second->children.size() > 1) {
			int leastCommonFields = 10000;
			cstring hdr1 = "";
			for (auto child : state.second->children) {
				if (hdr1 == "") hdr1 = child->firstHeaderExtracted;
				cstring hdr2 = child->firstHeaderExtracted;
				if (hdr1 != hdr2) {
					int commonFields = findCommonFields(headers[hdr1], headers[hdr2]);
					if (commonFields < leastCommonFields) 
						leastCommonFields = commonFields;
				}
			}
			const IR::Type_Header *childHdr = headers[hdr1];
			if (leastCommonFields > 0 && leastCommonFields < 10000) {
				// Add new fields to state and remove from children
				IR::IndexedVector<IR::StructField> *newHdrFields = new IR::IndexedVector<IR::StructField>();
				for (int pos = 0; pos < leastCommonFields; ++pos) {
					newHdrFields->push_back(childHdr->fields[pos]);
				}
				cstring newName = childHdr->name + COMMON_HDR + std::to_string(commonHdrNo);
				newHeaders[newName] = new IR::Type_Header(newName, *newHdrFields);
				headerExtractStates[newName] = new std::set<ParseStateInfo *>;
				++commonHdrNo;

				for (auto child : state.second->children) {
					headerExtractStates[newName]->insert(child);
					cstring childHdrName = child->firstHeaderExtracted;
					const IR::Type_Header *childHdr = headers[childHdrName];
					if (childHdr) {
						headerMap[childHdrName] = newName; 
						remappedFields[childHdrName] = new std::vector<cstring>();
						for (int pos = 0; pos < leastCommonFields; ++pos) {
							remappedFields[childHdrName]->push_back(childHdr->fields[pos]->name);
						}
						IR::IndexedVector<IR::StructField> *modifiedHdrFields = new IR::IndexedVector<IR::StructField>();
						for (int pos = leastCommonFields; pos < childHdr->fields.size(); ++pos) {
							modifiedHdrFields->push_back(childHdr->fields[pos]);
						}
						modifiedHeaders[childHdrName] = new IR::Type_Header(childHdrName, *modifiedHdrFields);
					}
				}
			}
		}
	}
	return parser;
}

IR::P4Program *CommonFields::postorder(IR::P4Program *p4p) {
	// Replace the headers and variables after commoning
	for (auto newHdr : newHeaders) {
		p4p = new IR::P4Program(*(p4p->apply(ModifyHeaders(*this, newHdr.first))));
	}
	for (auto modHdr : modifiedHeaders) {
		p4p = new IR::P4Program(*(p4p->apply(ModifyHeaders(*this, modHdr.first))));
	}

	return p4p;
}

}  // namespace P4