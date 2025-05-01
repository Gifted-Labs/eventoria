package com.giftedlabs.eventoria.events.repository.specs;


import com.giftedlabs.eventoria.enums.Category;
import com.giftedlabs.eventoria.enums.EventStatus;
import com.giftedlabs.eventoria.events.domain.Event;
import com.giftedlabs.eventoria.events.domain.Venue;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
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
            String keyword,
            List<Category> categories,
            List<EventStatus> eventStatuses,
            LocalDateTime startDateFrom,
            LocalDateTime startDateTo,
            LocalDateTime exactStartDate,
            LocalDateTime exactEndDate,
            Boolean isTicketed,
            Boolean isFreeOnly,
            Boolean isFeatured,
            Long organizerId,
            String city,
            String state,
            String country,
            Double longitude,
            Double latitude,
            Double radiusInKm,
            Double minPrice,
            Double maxPrice,
            Integer minCapacity,
            Integer maxCapacity,
            List<String> includeTags,
            List<String> excludeTags,
            Double minRating,
            Double maxRating,
            Integer minReviews,
            Boolean isVirtual) {

        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Keyword search in name or description
            if(keyword != null && !keyword.isEmpty()) {
                String likePattern = "%" + keyword.toLowerCase() + "%";
                Predicate namePredicate = criteriaBuilder.like(criteriaBuilder.lower(root.get("name")), likePattern);
                Predicate descriptionPredicate = criteriaBuilder.like(criteriaBuilder.lower(root.get("description")), likePattern);
                Predicate venuePredicate = criteriaBuilder.like(criteriaBuilder.lower(root.get("venue").get("venueName")), likePattern);
                predicates.add(criteriaBuilder.or(namePredicate, descriptionPredicate, venuePredicate));
            }

            // Category filter
            if(categories != null && !categories.isEmpty()) {
                predicates.add(criteriaBuilder.equal(root.get("category"), categories));
            }

            // City filter
            if(city != null && !city.isEmpty()) {
                predicates.add(criteriaBuilder.equal(root.get("venue").get("address").get("city"), city));
            }

            // Status filter
            if(eventStatuses!= null &&!eventStatuses.isEmpty()) {
                predicates.add(root.get("eventStatus").in(eventStatuses));
            }

            // Date Range filter
            if(startDateFrom != null && startDateTo != null) {
                predicates.add(criteriaBuilder.between(root.get("startTime"), startDateFrom, startDateTo));
            }

            // Date filters
            if (startDateFrom != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("startDate"), startDateFrom));
            }
            if (startDateTo != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("startDate"), startDateTo));
            }
            if (exactStartDate != null) {
                predicates.add(criteriaBuilder.equal(root.get("startDate"), exactStartDate));
            }
            if (exactEndDate != null) {
                predicates.add(criteriaBuilder.equal(root.get("endDate"), exactEndDate));
            }

            // Location filters
            if (city != null && !city.isEmpty()) {
                predicates.add(criteriaBuilder.equal(criteriaBuilder.lower(root.get("venue").get("address").get("city")), city.toLowerCase()));
            }

            if (state != null && !state.isEmpty()) {
                predicates.add(criteriaBuilder.equal(criteriaBuilder.lower(root.get("venue").get("address").get("state")), state.toLowerCase()));
            }
            if (country != null && !country.isEmpty()) {
                predicates.add(criteriaBuilder.equal(criteriaBuilder.lower(root.get("venue").get("address").get("country")), country.toLowerCase()));
            }
            if (latitude != null && longitude != null && radiusInKm != null) {
                double radiusInMeters = radiusInKm * 1000;
                predicates.add(criteriaBuilder.lessThanOrEqualTo(
                        criteriaBuilder.function("distance", Double.class,
                                criteriaBuilder.literal(latitude),
                                criteriaBuilder.literal(longitude),
                                root.get("venue").get("address").get("geolocation").get("latitude"),
                                root.get("venue").get("address").get("geolocation").get("longitude")),
                        radiusInMeters
                ));
            }

            // Price filters
            if (minPrice != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("price"), minPrice));
            }
            if (maxPrice != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("price"), maxPrice));
            }

            // Capacity filters
            if (minCapacity != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("venue").get("capacity"), minCapacity));
            }
            if (maxCapacity != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("venue").get("capacity"), maxCapacity));
            }

            // Tag filters
            if (includeTags != null && !includeTags.isEmpty()) {
                predicates.add(root.get("tags").in(includeTags));
            }
            if (excludeTags != null && !excludeTags.isEmpty()) {
                predicates.add(criteriaBuilder.not(root.get("tags").in(excludeTags)));
            }

            // Ticketed filter
            if(isTicketed != null) {
                predicates.add(criteriaBuilder.equal(root.get("isTicketed"), isTicketed));
            }
            // Free only filter
            if(isFreeOnly != null) {
                predicates.add(criteriaBuilder.equal(root.get("isFreeOnly"), isFreeOnly));

            }
            // Featured filter
            if(isFeatured != null) {
                predicates.add(criteriaBuilder.equal(root.get("isFeatured"), isFeatured));
            }

            if (isVirtual != null) {
                predicates.add(criteriaBuilder.equal(root.get("venue").get("isVirtual"), isVirtual));
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
