/**
 * Copyright (c) 2004, Peace Technology, Inc.
 * $Author:Tayag, Richard$
 * $Revision$
 * $Date$
 * $NoKeywords$
 */

package com.peacetech.templates.action;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.struts2.ServletActionContext;
import org.hibernate.Criteria;
import org.hibernate.Query;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.OracleCodec;
import org.springframework.beans.factory.annotation.Autowired;

import com.opensymphony.xwork2.ModelDriven;
import com.peacetech.dts.Document;
import com.peacetech.dts.PropertyDefinition;
import com.peacetech.dts.PropertyLookup;
import com.peacetech.dts.jdo.DocumentImpl;
import com.peacetech.dts.jdo.DocumentNodePropertyImpl;
import com.peacetech.jdo.query.QueryBuilder;
import com.peacetech.templates.filter.DocumentFilter;
import com.peacetech.templates.form.SearchDocumentForm;
import com.peacetech.templates.helpers.DocumentHelper;
import com.peacetech.templates.helpers.ForwardHelper;
import com.peacetech.templates.helpers.MenuHelper;
import com.peacetech.templates.helpers.QueryHelper;
import com.peacetech.templates.resources.Constants;
import com.peacetech.templates.security.SecurityHelper;
import com.peacetech.templates.utils.MainMenu;
import com.peacetech.templates.utils.StringUtil;
import com.peacetech.templates.utils.Utils;
import com.peacetech.webtools.taglib.menu.Menu;

import peacetech.gao.usorg.jdo.helpers.TextSearch;

public class SearchDocumentAction extends SearchAction implements ModelDriven<SearchDocumentForm> {
    public static final String QUERY_RESULT_MENU_NAME = "Query_Result_Menu";
    protected static final String PRINT = "print";
    protected static final String BACK = "back";
    protected static final Log logger = LogFactory.getLog(SearchDocumentAction.class);
    private SearchDocumentForm searchDocumentForm = new SearchDocumentForm();
    @Autowired
    DocumentHelper documentHelper;
    public SearchDocumentForm getSearchDocumentForm() {
        return searchDocumentForm;
    }

    public void setSearchDocumentForm(SearchDocumentForm searchDocumentForm) {
        this.searchDocumentForm = searchDocumentForm;
    }

    public String execute() throws Exception {
    	searchDocumentForm.setDocumentHelper(documentHelper);
        String cmd = searchDocumentForm.getCmd();

        if ("search".equalsIgnoreCase(cmd)) {
            return search(false);

        } else if ("clear".equalsIgnoreCase(cmd)) {
            return clear();

        } else if ("deleteDocuments".equalsIgnoreCase(cmd)) {
            return "deleteDocuments";

        } else if ("back".equalsIgnoreCase(cmd)) {
            return back();
        }
        return SUCCESS;

    }

    @Override
    public String search(boolean flgCheck) throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        String reqParam = searchDocumentForm.getCmd();

        if (!flgCheck) {
            isShowSystemDelete(request);
            if (!SecurityHelper.isLoggedInCanAccessDocument(request)) {
                return MainMenu.PERMISSION_ERROR_FORWARD_NAME;
            }
        }
        DocumentFilter filter = searchDocumentForm.getDocumentFilter();
        Codec ORACLE_CODEC = new OracleCodec();
        if (filter != null && searchDocumentForm.getDocumentFilter().isSearchPerformed()) {
            Set<DocumentNodePropertyImpl> properties  = new HashSet<>();
            //QueryBuilder qb = new QueryBuilder();
            String db="SELECT d FROM "+DocumentImpl.class.getName() +" d JOIN d.properties pProperty WHERE ";
            boolean isFirst = true;
            // document number
            if (searchDocumentForm.getDocumentFilter().getDocumentNumber() != null) {
                db = db+ " d.documentNumber like('%" + ESAPI.encoder().encodeForSQL( ORACLE_CODEC, filter.getDocumentNumber().toUpperCase() )+ "%')";
                searchDocumentForm.appendSearchCriteria("<b>Document Number:</b> ").appendSearchCriteria(filter.getDocumentNumber()).appendSearchCriteria(", ");
                isFirst = false;
            }

            if (filter.isPublished() != null) {
                if(!isFirst)
                    db = db+ " AND ";
                db = db+ " d.published = "+filter.isPublished();
                searchDocumentForm.appendSearchCriteria("<b>Status:</b> ").appendSearchCriteria(filter.getStatus()).appendSearchCriteria(", ");
                isFirst = false;
            }

            // document type
            if (filter.getType() != null) {
                PropertyDefinition docTypeDefinition = searchDocumentForm.jdo().getPropertyDefinition(Constants.Property.DOCTYPE.getCode());
                
                //qb.addAnd("pProperty.definition==" + qb.addParameter(PropertyDefinition.class, docTypeDefinition));
                //qb.addAnd("pProperty.value==" + qb.addParameter(String.class, filter.getType()));
                if(!isFirst){
                    db = db+ " AND ";
                }
//                Query propQuery = searchDocumentForm.getPm().getCurrentSession().createQuery("SELECT p FROM "+DocumentNodePropertyImpl.class.getName() +" p WHERE p.definition = :definition");
//                propQuery.setParameter("definition", docTypeDefinition);
//                properties = new HashSet<>(propQuery.list()); 
//                db = db+ " d.properties IN(:docTypeDefinitions)";
                db = db+ " pProperty.value = :value";
                isFirst = false;
                PropertyLookup typeLookup = searchDocumentForm.jdo().getPropertyLookup(docTypeDefinition.getName(), filter.getType());
                searchDocumentForm.appendSearchCriteria("<b>Type:</b> ").appendSearchCriteria(typeLookup.getDescription()).appendSearchCriteria(", ");
            }

            // Owner's name
            if (filter.getOwnerLastName() != null) {
                if(!isFirst){
                    db = db+ " AND ";
                }
                db = db+ " upper(d.preparer.lastName) like('%"+ESAPI.encoder().encodeForSQL( ORACLE_CODEC, filter.getOwnerLastName().toUpperCase())+"%')";
                isFirst = false;
                //qb.addAnd("preparer.lastName.matches(" + qb.addParameter(String.class, "(?i).*" + filter.getOwnerLastName() + ".*") + ")");
                searchDocumentForm.appendSearchCriteria("<b>Owner Last Name:</b> ").appendSearchCriteria(filter.getOwnerLastName()).appendSearchCriteria(", ");
            }

            if (filter.getOwnerFirstName() != null) {
                //qb.addAnd("preparer.firstName.matches(" + qb.addParameter(String.class, "(?i).*" + filter.getOwnerFirstName() + ".*") + ")");
                if(!isFirst){
                    db = db+ " AND ";
                }
                db = db+ " upper(d.preparer.firstName) like('%"+ESAPI.encoder().encodeForSQL( ORACLE_CODEC, filter.getOwnerFirstName().toUpperCase())+"%')";
                isFirst = false;
                searchDocumentForm.appendSearchCriteria("<b>Owner First Name:</b> ").appendSearchCriteria(filter.getOwnerFirstName()).appendSearchCriteria(", ");
            }

            // fiscal year
            if (filter.getFiscalYear() != null) {
                //qb.addAnd("fiscalYear==" + qb.addParameter(Integer.class, Utils.toInt(filter.getFiscalYear())));
                if(!isFirst){
                    db = db+ " AND ";
                }
                db = db+ " d.fiscalYear ="+ESAPI.encoder().encodeForSQL( ORACLE_CODEC, filter.getFiscalYear());
                isFirst = false;
                searchDocumentForm.appendSearchCriteria("<b>Fiscal Year:</b> ").appendSearchCriteria(filter.getFiscalYear()).appendSearchCriteria(", ");
            }
            QueryBuilder queryBuild = new QueryBuilder();
            // create date
            QueryHelper.addDateConstraints(queryBuild, filter.getCreateDateOption(), filter.getCreateDateStartDateString(), filter.getCreateDateEndDateString(), "d.createDate");
            searchDocumentForm.appendSearchCriteria(QueryHelper.getDateCriteria(filter.getCreateDateOption(), filter.getCreateDateStartDateString(), filter.getCreateDateEndDateString(), "Creation Date"));

            // publish date
            QueryHelper.addDateConstraints(queryBuild, filter.getPublishDateOption(), filter.getPublishDateStartDateString(), filter.getPublishDateEndDateString(), "d.publishDate");
            searchDocumentForm.appendSearchCriteria(QueryHelper.getDateCriteria(filter.getPublishDateOption(), filter.getPublishDateStartDateString(), filter.getPublishDateEndDateString(), "Finalized Date"));

            // document title
            String searchExpression = TextSearch.getWildcardAndTextSearch(filter.getTitle());
            if (!Utils.isBlank(searchExpression)) {
            	
//                String titleExpression = StringUtil.getQuotedString("contains(title , '" + searchExpression + "', 1) > 0", '"', '\\');
//                queryBuild.addAnd("ext:sqlExp(" + titleExpression + ")");
                queryBuild.addAnd(" upper(d.title) like '%"+ESAPI.encoder().encodeForSQL( ORACLE_CODEC, filter.getTitle().toUpperCase())+"%'");
                searchDocumentForm.appendSearchCriteria("<b>Document Title:</b> ").appendSearchCriteria(filter.getTitle()).appendSearchCriteria(", ");
            }

            if (!Utils.isBlank(filter.getInstitute())) {
                List<peacetech.gao.usorg.jdo.OrgUnit> list = new ArrayList<peacetech.gao.usorg.jdo.OrgUnit>();
                list.add(SecurityHelper.getNihorgOrgUnit(searchDocumentForm.nihorgPm(), filter.getInstitute()));
                SecurityHelper.addOrgUnitConstraints(searchDocumentForm.pm(), list, queryBuild, true);
            } else {
                SecurityHelper.addIcSecurity(request, searchDocumentForm.pm(), searchDocumentForm.nihorgPm(), queryBuild);
            }
//            queryBuild.setOrdering("documentNumber asc");
            if(!isFirst)
            	db = db+" AND ";
            db = db+ queryBuild.toString();
//            if(queryBuild.toString()!= " 1=1 ")
//            db = db.replace(" 1=1 ", "");
//            searchDocumentForm.getPm().getCurrentSession().createCriteria(DocumentImpl.class).setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY);
            Query query = searchDocumentForm.getPm().getCurrentSession().createQuery(db + " order by d.documentNumber asc");
            if(db.contains(":value")){
//                query.setParameter("docTypeDefinitions",properties);
                query.setParameter("value",filter.getType());
            }
            List result = (List) query.list().stream().distinct().collect(Collectors.toList());
                   
            searchDocumentForm.setList(result);
        }

        return SEARCH;
    }

    public String clear() throws Exception {
        searchDocumentForm.getDocumentFilter().clearAll();
        return search(false);
    }

    public String back() throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        Menu mainMenu = MenuHelper.getMainMenu(request, getTexts());
        return ForwardHelper.getActionForward(MenuHelper.getPriorSubMenuActionSubMenuBack(mainMenu, request));
    }

    @Override
    public SearchDocumentForm getModel() {

        return searchDocumentForm;
    }

    private void isShowSystemDelete(HttpServletRequest request) {
        if (searchDocumentForm.getShowSystemDelete() == null) {
            System.out.println("main menu" + MenuHelper.getMainMenu(request, getTexts()));
            Menu priorMenu = MenuHelper.getMainMenu(request, getTexts()).getSelectedItem().getSubMenu();
            String priorMenuName = priorMenu == null ? null : priorMenu.getName();
            searchDocumentForm.setShowSystemDelete(SecurityHelper.isLoggedInCanDeleteDocument(request) && MainMenu.SYSTEM_ADMIN_SUBMENU_NAME.equals(priorMenuName));
        }
    }

}
