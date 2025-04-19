package com.giftedlabs.eventoria.events.repository.specs;


import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Venue;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.criteria.Predicate;


/**
 * EventSpecification is a builder for Event entities to enable complex dynamic queries.
 */
public class EventSpecification {

    /**
     * Build a specification with multiple optional criteria
     */
    public static Specification<Event> buildSpecification(
            String keyword, Category category,
            String city, String startDate, String endDate,
            Boolean isTicketed, Boolean isFeatured,
            List<EventStatus> status,Long organizerId){

        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Keyword search in name or description
            if(keyword != null && !keyword.isEmpty()) {
                String likePattern = "%" + keyword.toLowerCase() + "%";
                Predicate namePredicate = criteriaBuilder.like(criteriaBuilder.lower(root.get("name")), likePattern);
                Predicate description = criteriaBuilder.like(criteriaBuilder.lower(root.get("description")), likePattern);
                predicates.add(criteriaBuilder.or(namePredicate,description));
            }

            // Category filter
            if(category != null) {
                predicates.add(criteriaBuilder.equal(root.get("category"), category));
            }

            // City filter
            if(city != null && !city.isEmpty()) {
                predicates.add(criteriaBuilder.equal(root.get("venue").get("address").get("city"), city));
            }

            // Start Date range filter
            if(startDate != null && !startDate.isEmpty()) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("startTime"), startDate));
            }

            // EndDate range filter
            if(endDate != null && !endDate.isEmpty()) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("endTime"), endDate));
            }

            // EventStatus filter
            if(status != null && !status.isEmpty()){
                predicates.add(root.get("eventStatus").in(status));
            }

            // Ticketed filter
            if(isTicketed != null) {
                predicates.add(criteriaBuilder.equal(root.get("isTicketed"), isTicketed));
            }

            // Featured filter
            if(isFeatured != null) {
                predicates.add(criteriaBuilder.equal(root.get("isFeatured"), isFeatured));
            }

            // Organizer filter
            if(organizerId != null){
                Join<Object, Object> organizerJoin = root.join("organizer", JoinType.INNER);
                predicates.add(criteriaBuilder.equal(organizerJoin.get("id"), organizerId));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    /**
     * Build a specification for searching events by venue
     */
    public static Specification<Event> searchByVenue(String venueName) {
        return (root, query, criteriaBuilder) -> {
            Join<Event, Venue> venueJoin = root.join("venue", JoinType.INNER);
            return criteriaBuilder.like(criteriaBuilder.lower(venueJoin.get("venueName")), "%" + venueName.toLowerCase() + "%");
        };
    }

}
